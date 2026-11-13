// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

// Guided first-run setup for a DeskID token, in the shape macOS uses for
// Touch ID: one thing per screen, a live picture of the sensor, and no step
// that cannot be undone.
//
//     tools/deskid-setup            build "DeskID Setup.app" and open it
//     tools/deskid-setup --check    run the self-test and exit
//
// The app talks to the board itself through CryptoTokenKit, the same stack
// macOS uses at the login window, so it needs no python, no repository and
// no Terminal — only the smart-card entitlement the launcher signs in.
// Pairing goes through `sc_auth`, which is the one tool Apple gives for it.

import CryptoKit
import CryptoTokenKit
import Security
import SwiftUI

// MARK: - Talking to the device

enum DeviceError: LocalizedError {
    case noAccess, noReader, cardBusy, shortResponse, refused(UInt16)

    var errorDescription: String? {
        switch self {
        case .noAccess:
            return "This build cannot see smart cards. Launch it with tools/deskid-setup, "
                + "which signs in the entitlement."
        case .noReader: return "DeskID is not connected."
        case .cardBusy: return "Another process holds the card. Close it and try again."
        case .shortResponse: return "The device sent a truncated answer."
        case .refused(let sw): return String(format: "The device answered %04X.", sw)
        }
    }
}

/// The PIV/DeskID APDUs the setup needs, byte for byte as hw_smoke_test.py sends them.
enum APDU {
    static let selectDeskID = Data([0x00, 0xA4, 0x04, 0x00, 0x07,
                                    0xF0, 0x44, 0x65, 0x73, 0x6B, 0x49, 0x44])  // F0 "DeskID"
    /// Older firmware and bring-up boards answer the standard PIV AID instead.
    static let selectPIV = Data([0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08])
    static let enrollStep = Data([0x80, 0xE1, 0x00, 0x00, 0x00])
    static let statusTag: [UInt8] = [0x5F, 0xFF, 0x01]
    static let certificateTag: [UInt8] = [0x5F, 0xC1, 0x05]

    static func getData(_ tag: [UInt8]) -> Data {
        Data([0x00, 0xCB, 0x3F, 0xFF, UInt8(tag.count + 2), 0x5C, UInt8(tag.count)] + tag + [0x00])
    }

    /// Ask the board to watch its own sensor for `seconds`. Not gated: it
    /// releases nothing, it only makes an early touch possible on a board
    /// whose wake line cannot be trusted.
    static func armRing(_ seconds: UInt8) -> Data {
        Data([0x80, 0xE3, 0x00, 0x00, 0x01, seconds])
    }

    static func generalAuthenticate(_ digest: Data) -> Data {
        let body = Data([0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]) + digest
        return Data([0x00, 0x87, 0x11, 0x9A, UInt8(body.count)]) + body + Data([0x00])
    }
}

/// Flat BER-TLV walk. Single-byte tags are all the PIV objects use.
func tlv(_ data: Data) -> [UInt8: Data] {
    let bytes = [UInt8](data)
    var values: [UInt8: Data] = [:]
    var i = 0
    while i + 2 <= bytes.count {
        let tag = bytes[i]
        var length = Int(bytes[i + 1])
        i += 2
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard i + count <= bytes.count else { break }
            length = bytes[i..<i + count].reduce(0) { $0 << 8 | Int($1) }
            i += count
        }
        guard i + length <= bytes.count else { break }
        values[tag] = Data(bytes[i..<i + length])
        i += length
    }
    return values
}

func number(_ data: Data?) -> Int { (data ?? Data()).reduce(0) { $0 << 8 | Int($1) } }

/// What the board says about itself, as `GET DATA 5FFF01` returns it.
struct DeviceStatus {
    var firmware = ""
    var variant = -1
    var sensorReady = false
    var credential = false
    var failures = 0
    var lockout = 0
    var templates = 0
    /// Seconds an already-given touch stays spendable. Non-zero means the next
    /// prompt will be answered with no wait at all.
    var touchHeldSeconds = 0
    /// The R503 WAKEUP line. Low means it was never soldered, and the board's
    /// idle scan — everything touch-first depends on — cannot run.
    var wakeLineWired = false

    var variantName: String {
        ["production", "deskid", "bringup"].indices.contains(variant)
            ? ["production", "deskid", "bringup"][variant] : "unknown"
    }

    /// deskid-bringup approves every presence request with no sensor at all,
    /// so it must never be paired to a login.
    var isBringup: Bool { variant == 2 }

    init() {}

    init(fields: [UInt8: Data]) {
        firmware = String(decoding: fields[0x01] ?? Data(), as: UTF8.self)
        variant = number(fields[0x02])
        sensorReady = number(fields[0x06]) == 1
        credential = number(fields[0x08]) != 0
        failures = number(fields[0x09])
        lockout = number(fields[0x0A])
        templates = number(fields[0x0B])
        touchHeldSeconds = number(fields[0x12])
        wakeLineWired = number(fields[0x0C]) != 0
    }
}

struct SignResult {
    let status: UInt16
    let seconds: Double
    let verified: Bool
}

/// One open session with the card. Every call drains `61xx` continuations.
struct Session {
    let card: TKSmartCard

    func send(_ apdu: Data) async throws -> (data: Data, status: UInt16) {
        var response = try await card.transmit(apdu)
        var data = Data()
        while response.count >= 2, response[response.count - 2] == 0x61 {
            data += response.dropLast(2)
            response = try await card.transmit(Data([0x00, 0xC0, 0x00, 0x00, response.last!]))
        }
        guard response.count >= 2 else { throw DeviceError.shortResponse }
        data += response.dropLast(2)
        let tail = [UInt8](response.suffix(2))
        return (data, UInt16(tail[0]) << 8 | UInt16(tail[1]))
    }

    func armRing(_ seconds: UInt8) async throws {
        _ = try await send(APDU.armRing(seconds))
    }

    func status() async throws -> DeviceStatus {
        let (data, sw) = try await send(APDU.getData(APDU.statusTag))
        guard sw == 0x9000 else { throw DeviceError.refused(sw) }
        return DeviceStatus(fields: tlv(tlv(data)[0x53] ?? Data()))
    }
}

enum Device {
    static let presenceTimeout = 30.0  // kAuthenticationTimeoutMilliseconds in src/main.cpp
    static let earlyTouchWindow = presenceTimeout  // kEarlyTouchValidMilliseconds in src/main.cpp
    static let enrollTimeout = 60.0
    static let enrollFailureLimit = 3

    static let stages: [UInt8: String] = [
        0x00: "Place your finger on the sensor",
        0x01: "Captured — now lift your finger",
        0x02: "Touch the same finger again",
        0x03: "Enrolled and stored",
        0xFF: "That attempt failed — starting over",
    ]

    static var readerName: String? {
        TKSmartCardSlotManager.default?.slotNames.first { $0.contains("DeskID") }
    }

    /// Opens the card, selects the PIV applet, runs `body`, and always closes.
    static func withCard<T>(_ body: (Session) async throws -> T) async throws -> T {
        guard let manager = TKSmartCardSlotManager.default else { throw DeviceError.noAccess }
        guard let name = readerName,
              let slot = await manager.getSlot(withName: name),
              let card = slot.makeSmartCard()
        else { throw DeviceError.noReader }
        guard try await card.beginSession() else { throw DeviceError.cardBusy }
        defer { card.endSession() }
        let session = Session(card: card)
        if try await session.send(APDU.selectDeskID).status != 0x9000 {
            _ = try await session.send(APDU.selectPIV)
        }
        return try await body(session)
    }

    static func status() async throws -> DeviceStatus {
        try await withCard { try await $0.status() }
    }

    /// The X.509 certificate the board serves for slot 9A, as DER.
    static func certificate() async throws -> Data {
        try await withCard { session in
            let (object, sw) = try await session.send(APDU.getData(APDU.certificateTag))
            guard sw == 0x9000, let der = tlv(tlv(object)[0x53] ?? Data())[0x70]
            else { throw DeviceError.refused(sw) }
            return der
        }
    }

    /// Drives `80 E1` until the sensor stores a template. Reports each stage
    /// change as it happens, and only claims success once the template count
    /// has actually gone up.
    static func enroll(progress: @MainActor @escaping (UInt8, String) -> Void) async throws
        -> (enrolled: Bool, problem: String)
    {
        try await withCard { session in
            let before = try await session.status().templates
            let deadline = Date().addingTimeInterval(enrollTimeout)
            var stage: UInt8?
            var failures = 0
            var problem = "no enrollment within \(Int(enrollTimeout)) s"
            while Date() < deadline {
                let (data, sw) = try await session.send(APDU.enrollStep)
                guard sw == 0x9000, data.count == 1 else {
                    problem = explain(sw)
                    break
                }
                if data[0] != stage {
                    stage = data[0]
                    let message = stages[data[0]] ?? String(format: "Unknown stage %02X", data[0])
                    await progress(data[0], message)
                    if data[0] == 0xFF { failures += 1 }
                }
                if stage == 0x03 { problem = ""; break }
                if failures >= enrollFailureLimit {
                    problem = "\(failures) attempts failed in a row"
                    break
                }
                try await Task.sleep(nanoseconds: 250_000_000)
            }
            let after = try await session.status().templates
            return (problem.isEmpty && after > before, problem)
        }
    }

    /// The whole product in one exchange: ask for a P-256 signature over a
    /// random digest and verify it against the certificate the board serves.
    static func sign() async throws -> SignResult {
        try await withCard { session in
            var digest = Data(count: 32)
            _ = digest.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            let started = Date()
            let (data, sw) = try await session.send(APDU.generalAuthenticate(digest))
            let seconds = Date().timeIntervalSince(started)
            guard sw == 0x9000 else { return SignResult(status: sw, seconds: seconds, verified: false) }
            let signature = tlv(tlv(data)[0x7C] ?? Data())[0x82] ?? Data()
            let (object, _) = try await session.send(APDU.getData(APDU.certificateTag))
            let der = tlv(tlv(object)[0x53] ?? Data())[0x70] ?? Data()
            return SignResult(status: sw, seconds: seconds,
                              verified: verify(digest: digest, signature: signature, certificate: der))
        }
    }

    private static func verify(digest: Data, signature: Data, certificate: Data) -> Bool {
        guard let certificate = SecCertificateCreateWithData(nil, certificate as CFData),
              let key = SecCertificateCopyKey(certificate)
        else { return false }
        return SecKeyVerifySignature(key, .ecdsaSignatureDigestX962SHA256,
                                     digest as CFData, signature as CFData, nil)
    }

    static func explain(_ statusWord: UInt16) -> String {
        switch statusWord {
        case 0x6982:
            return "The device waited and saw no matching finger. "
                + "Tap and lift — do not press and hold — with a finger you enrolled."
        case 0x6983:
            return "Too many failed matches in a row, so the sensor is locked out. "
                + "Wait for the lockout to run down, then try again."
        case 0x6D00:
            return "This image is deskid-bringup, which has no sensor."
        default:
            return String(format: "The device answered %04X.", statusWord)
        }
    }
}

// MARK: - Pairing through sc_auth

enum ToolError: LocalizedError {
    case failed(String)
    var errorDescription: String? {
        switch self { case .failed(let text): return text }
    }
}

enum Pairing {
    struct State {
        var identityHash = ""
        var pairedHashes: [String] = []
        var soleAdministrator = false
        /// Which token driver macOS handed the card to, e.g. "dev.deskid.setup.token"
        /// or "com.apple.pivtoken". Only DeskID's own driver skips the PIN.
        var driver = ""
        var driverInstalled = false
        /// `sc_auth enable_for_login -c <class-id>`. Pairing is only half of
        /// it: SecurityAgent offers a third-party token class only once it has
        /// been told the class exists, so until this is set the login window,
        /// the lock screen and every admin prompt draw the account password
        /// field with a perfectly paired card sitting in the reader.
        var loginEnabled = false
        /// Smart-card unlock of the FileVault preboot screen, which runs
        /// before ctkd and therefore before this driver exists. The one gate
        /// that can be paired, enabled, and still ask for a password.
        var fileVaultEnabled = false

        var driverIsDeskID: Bool { driver == "dev.deskid.setup.token" }
    }

    static let driverID = "dev.deskid.setup.token"

    static let lsregister = "/System/Library/Frameworks/CoreServices.framework"
        + "/Frameworks/LaunchServices.framework/Support/lsregister"

    /// `sc_auth enable_for_login -c <class-id>` is, in full, three lines of
    /// bash: resolve the class id to a path with `pluginkit`, walk up to the
    /// containing app, and `lsregister -trusted` it. It records nothing, so
    /// there is nothing to read back — hence this flag, set when the step is
    /// known to have run. Going straight to `lsregister` skips the
    /// `pluginkit` lookup, which is the part that fails under elevation:
    /// privileged helpers have no connection to the per-user `pkd`, and
    /// `sc_auth` then reports the token as simply not found.
    static let loginEnabledKey = "loginEnabled"

    static let user = NSUserName()

    static func state() throws -> State {
        var state = State()
        state.identityHash = hashes(in: try run("/usr/sbin/sc_auth", ["identities"])).first ?? ""
        state.pairedHashes = hashes(in: (try? run("/usr/sbin/sc_auth", ["list", "-u", user])) ?? "")
        let admins = (try? run("/usr/bin/dscl", [".", "-read", "/Groups/admin", "GroupMembership"]))?
            .split(whereSeparator: { $0 == " " || $0 == "\n" })
            .dropFirst()
            .filter { $0 != "root" && !$0.hasPrefix("_") } ?? []
        state.soleAdministrator = admins.count < 2
        state.driver = ((try? run("/usr/bin/security", ["list-smartcards"])) ?? "")
            .split(separator: "\n").first.map { String($0.split(separator: ":").first ?? "") } ?? ""
        state.driverInstalled = ((try? run("/usr/bin/pluginkit", ["-m", "-i", driverID])) ?? "")
            .contains(driverID)
        state.loginEnabled = UserDefaults.standard.bool(forKey: loginEnabledKey)
        let fileVault = ((try? run("/usr/sbin/sc_auth", ["filevault", "-o", "status", "-u", user])) ?? "")
            .lowercased()
        state.fileVaultEnabled = fileVault.contains("enabled") && !fileVault.contains("not")
        return state
    }

    /// Registers the token extension bundled inside this app. macOS only loads
    /// extensions from an installed app, so a copy outside /Applications is
    /// moved there first. Takes effect on the next card insertion.
    static func installDriver() throws {
        var app = Bundle.main.bundleURL
        if !app.path.hasPrefix("/Applications/") {
            let target = URL(fileURLWithPath: "/Applications").appendingPathComponent(app.lastPathComponent)
            try? FileManager.default.removeItem(at: target)
            try FileManager.default.copyItem(at: app, to: target)
            app = target
        }
        let appex = app.appendingPathComponent("Contents/PlugIns/DeskIDToken.appex")
        _ = try run(lsregister, ["-f", app.path])
        _ = try run("/usr/bin/pluginkit", ["-a", appex.path])
        _ = try run("/usr/bin/pluginkit", ["-e", "use", "-i", driverID])
        // Trusting the bundle is part of installing the driver, not of
        // pairing: an untrusted class is never offered at a SecurityAgent
        // prompt, whoever is paired. `pair` repeats it because that is the
        // step whose whole promise is that the login gate now works, and the
        // command is idempotent.
        _ = try run(lsregister, ["-trusted", app.path])
        UserDefaults.standard.set(true, forKey: loginEnabledKey)
    }

    /// `sc_auth pair` rewrites how this account authenticates, so it is
    /// verified straight away and unwound if the system disagrees with it.
    ///
    /// `enable_for_login` runs first and under the same authorisation, because
    /// pairing without it is the failure this app existed to prevent: every
    /// gate keeps asking for the password and nothing in `sc_auth pair`,
    /// `sc_auth list` or `security list-smartcards` says why.
    static func pair(hash: String) throws {
        let command = "\(quoted(lsregister)) -trusted \(quoted(Bundle.main.bundleURL.path))"
            + " && /usr/sbin/sc_auth pair -u \(quoted(user)) -h \(quoted(hash))"
        _ = try run("/usr/bin/osascript", [
            "-e", "do shell script \(appleScriptQuoted(command)) with administrator privileges",
        ])
        guard hashes(in: (try? run("/usr/sbin/sc_auth", ["list", "-u", user])) ?? "").contains(hash)
        else {
            _ = try? run("/usr/sbin/sc_auth", ["unpair", "-u", user, "-h", hash])
            throw ToolError.failed("Pairing reported success but macOS does not list the card. "
                                   + "Nothing was changed.")
        }
        UserDefaults.standard.set(true, forKey: loginEnabledKey)
    }

    static func unpair() throws {
        _ = try run("/usr/sbin/sc_auth", ["unpair", "-u", user])
    }

    /// Every 40-hex-digit word at the start of a line.
    static func hashes(in text: String) -> [String] {
        text.split(separator: "\n").compactMap { line in
            let word = line.trimmingCharacters(in: .whitespaces)
                .split(whereSeparator: { $0 == "\t" || $0 == " " }).first.map(String.init) ?? ""
            return word.count == 40 && word.allSatisfy(\.isHexDigit) ? word : nil
        }
    }

    static func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let text = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            if text.contains("User canceled") { throw ToolError.failed("Cancelled.") }
            if text.contains("6982") {
                throw ToolError.failed("The device saw no matching finger within "
                                       + "\(Int(Device.presenceTimeout)) s, so macOS refused to pair. "
                                       + "Nothing was changed.")
            }
            let last = text.split(separator: "\n").last(where: {
                !$0.trimmingCharacters(in: .whitespaces).isEmpty
            })
            throw ToolError.failed(last.map(String.init) ?? "\(executable) exited \(process.terminationStatus)")
        }
        return text
    }

    private static func quoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func appleScriptQuoted(_ value: String) -> String {
        "\"" + value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

// MARK: - Flow

enum Step: Int, CaseIterable {
    case connect, fingerprint, test, login, done
}

/// How the sensor artwork reads right now.
enum Ring {
    case idle, waiting, success, failure

    var tint: Color {
        switch self {
        case .idle: return .secondary
        case .waiting: return .accentColor
        case .success: return .green
        case .failure: return .red
        }
    }
}

@MainActor
final class Setup: ObservableObject {
    @Published var step: Step = .connect
    @Published var status: DeviceStatus?
    @Published var reader: String?
    @Published var busy = false
    @Published var ring: Ring = .idle
    @Published var progress: Double = 0
    @Published var headline = ""
    @Published var detail = ""
    @Published var failure: String?
    @Published var pairing = Pairing.State()

    var connected: Bool { status != nil }
    var paired: Bool { !pairing.pairedHashes.isEmpty }

    // MARK: Device

    /// Reads 5FFF01. Quiet by design: it runs on a timer while the first
    /// screen is up, so a failure here is "not plugged in yet", not an error.
    func refresh() async {
        reader = Device.readerName
        do {
            status = reader == nil ? nil : try await Device.status()
        } catch DeviceError.noAccess {
            status = nil
            failure = DeviceError.noAccess.errorDescription
        } catch {
            // Assign even when nothing answered: a token that has been
            // unplugged has to stop being reported as present.
            status = nil
        }
    }

    func enroll() async {
        busy = true
        failure = nil
        ring = .waiting
        progress = 0
        if (status?.templates ?? 0) > 0 {
            headline = "Touch a finger you already enrolled"
            detail = "The device asks an existing finger to vouch for the new one first."
        } else {
            headline = "Place your finger on the sensor"
            detail = "Tap and lift when asked. This takes a few seconds."
        }
        defer { busy = false }

        var enrolled = false
        do {
            let result = try await Device.enroll { [weak self] stage, message in
                self?.apply(stage: stage, message: message)
            }
            enrolled = result.enrolled
            if !enrolled { detail = result.problem }
        } catch {
            failure = error.localizedDescription
        }

        ring = enrolled ? .success : .failure
        progress = enrolled ? 1 : 0
        headline = enrolled ? "Fingerprint added" : "That didn't take"
        if enrolled { detail = "You can add another finger or move on." }
        await refresh()
    }

    private func apply(stage: UInt8, message: String) {
        switch stage {
        case 0x00: progress = 0.08
        case 0x01: progress = 0.4
        case 0x02: progress = 0.7
        case 0x03: progress = 1
        default: progress = max(progress, 0.08)
        }
        ring = stage == 0xFF ? .failure : .waiting
        headline = message
    }

    /// The whole product in one gesture: ask for a signature and touch the
    /// sensor. Also the honest rehearsal for what pairing will demand.
    func testSignature() async {
        busy = true
        failure = nil
        ring = .waiting
        progress = 0
        headline = "Touch the sensor"
        detail = "The ring on the device is lit. You have about "
            + "\(Int(Device.presenceTimeout)) seconds."
        defer { busy = false }

        var signed = false
        do {
            let result = try await Device.sign()
            signed = result.status == 0x9000 && result.verified
            detail = signed
                ? String(format: "Verified against the device certificate in %.1f s.", result.seconds)
                : result.status == 0x9000
                    ? "The device signed, but the signature does not match its certificate."
                    : Device.explain(result.status)
            if signed, result.seconds < 1 {
                detail += " That was instant — no finger was asked for, which means deskid-bringup."
            }
        } catch {
            failure = error.localizedDescription
        }

        ring = signed ? .success : .failure
        progress = signed ? 1 : 0
        headline = signed ? "It signed" : "No signature"
        await refresh()
    }

    // MARK: Pairing

    /// `sc_auth` and `dscl` take long enough to stutter the window if they
    /// run on the main actor.
    func reloadPairing() async {
        do {
            pairing = try await offMain { try Pairing.state() }
        } catch {
            failure = error.localizedDescription
        }
    }

    func pair() async {
        busy = true
        failure = nil
        ring = .waiting
        headline = "Touch the sensor when the ring lights"
        detail = "macOS asks for your password first. Pairing then asks the "
            + "device to sign, and that needs your finger."
        defer { busy = false }

        let hash = pairing.identityHash
        do {
            try await offMain { try Pairing.pair(hash: hash) }
            ring = .success
            headline = "Paired"
            detail = "Your Mac will accept DeskID at the login window after a "
                + "logout, at the lock screen, and for admin prompts. The "
                + "FileVault screen at boot still asks for your password."
        } catch {
            ring = .failure
            headline = "Not paired"
            failure = error.localizedDescription
        }
        await reloadPairing()
    }

    func installDriver() async {
        busy = true
        failure = nil
        defer { busy = false }
        do {
            try await offMain { try Pairing.installDriver() }
            headline = "Driver installed"
            detail = "Unplug DeskID and plug it back in so macOS hands the card to it."
        } catch {
            failure = error.localizedDescription
        }
        await reloadPairing()
    }

    func unpair() async {
        busy = true
        failure = nil
        defer { busy = false }
        do {
            try await offMain { try Pairing.unpair() }
            ring = .idle
            headline = "Unpaired"
            detail = "Your Mac is back to password login."
        } catch {
            failure = error.localizedDescription
        }
        await reloadPairing()
    }

    /// `sc_auth pair` blocks on an admin dialog, so it cannot run on the main actor.
    private func offMain<T>(_ body: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try body() })
            }
        }
    }

    // MARK: Navigation

    func go(to next: Step) {
        step = next
        ring = .idle
        progress = 0
        failure = nil
        headline = ""
        detail = ""
        if next == .login { Task { await reloadPairing() } }
    }
}

// MARK: - The sensor, drawn

/// The one piece of artwork in the app. It is the sensor: the ring around it
/// fills as enrollment progresses and breathes while the device is waiting for
/// a finger, which is the only cue macOS itself will ever give.
struct SensorArtwork: View {
    let ring: Ring
    let progress: Double

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var breathing = false

    private var settle: Animation { .spring(response: 0.4, dampingFraction: 1) }

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.primary.opacity(0.08), lineWidth: 6)

            Circle()
                .trim(from: 0, to: max(progress, ring == .success ? 1 : 0))
                .stroke(ring.tint, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(settle, value: progress)

            Image(systemName: ring == .failure ? "exclamationmark.circle" : "touchid")
                .font(.system(size: 68, weight: .thin))
                .foregroundStyle(ring.tint)
                .contentTransition(.symbolEffect(.replace))
                .animation(settle, value: ring)
        }
        .frame(width: 132, height: 132)
        .scaleEffect(breathing ? 1.04 : 1)
        .animation(settle, value: ring)
        .onChange(of: ring) { updateBreathing() }
        .onAppear { updateBreathing() }
        .accessibilityLabel(label)
    }

    private func updateBreathing() {
        guard ring == .waiting, !reduceMotion else {
            withAnimation(settle) { breathing = false }
            return
        }
        withAnimation(.easeInOut(duration: 1.1).repeatForever(autoreverses: true)) {
            breathing = true
        }
    }

    private var label: String {
        switch ring {
        case .idle: return "Sensor idle"
        case .waiting: return "Waiting for your finger"
        case .success: return "Accepted"
        case .failure: return "Refused"
        }
    }
}

/// Where am I, how many left. Five dots, no numbers to read.
struct StepDots: View {
    let step: Step

    var body: some View {
        HStack(spacing: 7) {
            ForEach(Step.allCases, id: \.rawValue) { each in
                Circle()
                    .fill(each.rawValue <= step.rawValue
                          ? Color.accentColor : Color.primary.opacity(0.15))
                    .frame(width: 6, height: 6)
            }
        }
        .animation(.spring(response: 0.4, dampingFraction: 1), value: step)
        .accessibilityLabel("Step \(step.rawValue + 1) of \(Step.allCases.count)")
    }
}

/// A labelled fact about the device. Grouping by proximity, not by border.
struct Fact: View {
    let name: String
    let value: String
    var warn = false

    var body: some View {
        HStack {
            Text(name).foregroundStyle(.secondary)
            Spacer(minLength: 16)
            Text(value)
                .foregroundStyle(warn ? Color.orange : Color.primary)
                .fontWeight(warn ? .semibold : .regular)
        }
        .font(.callout)
        .monospacedDigit()
    }
}

struct Title: View {
    let text: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 8) {
            Text(text)
                .font(.system(size: 26, weight: .semibold))
                .tracking(-0.4)
                .multilineTextAlignment(.center)
            Text(subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Said once, in the place it matters, rather than in a dialog to dismiss.
struct Warning: View {
    let text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Text(text)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .font(.footnote)
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))
    }
}

// MARK: - Screens

struct ConnectScreen: View {
    @EnvironmentObject private var setup: Setup

    var body: some View {
        VStack(spacing: 22) {
            SensorArtwork(ring: setup.connected ? .success : .idle,
                          progress: setup.connected ? 1 : 0)
            Title(text: "Connect DeskID",
                  subtitle: setup.connected
                    ? "Found it. Here is what the device says about itself."
                    : "Plug the token into a USB port. This screen updates on its own.")

            if let status = setup.status {
                VStack(spacing: 9) {
                    Fact(name: "Reader", value: setup.reader ?? "—")
                    Fact(name: "Firmware", value: status.firmware)
                    Fact(name: "Image", value: status.variantName, warn: status.isBringup)
                    Fact(name: "Sensor", value: status.sensorReady ? "ready" : "not answering",
                         warn: !status.sensorReady && !status.isBringup)
                    Fact(name: "Certificate", value: status.credential ? "present" : "missing",
                         warn: !status.credential)
                    Fact(name: "Fingerprints", value: "\(status.templates)")
                    if status.lockout > 0 {
                        Fact(name: "Locked out", value: "\(status.lockout) s", warn: true)
                    }
                }
                .padding(.horizontal, 4)

                if status.isBringup {
                    Warning("""
                        This board runs deskid-bringup, which approves every \
                        request without a sensor. Flash the deskid image before \
                        pairing it to your Mac.
                        """)
                } else if !status.sensorReady {
                    Warning("""
                        The fingerprint sensor is not answering, so every match \
                        will fail. Check the five wires against the labels in the \
                        README, then unplug and replug.
                        """)
                }
                if !status.credential {
                    Warning("""
                        There is no certificate on this board, so macOS cannot \
                        see an identity. Issue one first:  \
                        tools/provision.py --on-device
                        """)
                }
            } else {
                ProgressView().controlSize(.small)
            }
        }
    }
}

struct FingerprintScreen: View {
    @EnvironmentObject private var setup: Setup

    private var enrolled: Int { setup.status?.templates ?? 0 }
    private var canEnroll: Bool {
        !setup.busy && setup.status?.sensorReady == true && setup.status?.lockout == 0
    }

    var body: some View {
        VStack(spacing: 22) {
            SensorArtwork(ring: setup.ring, progress: setup.progress)
            Title(text: setup.headline.isEmpty ? "Add a Fingerprint" : setup.headline,
                  subtitle: setup.detail.isEmpty ? defaultSubtitle : setup.detail)

            Button(enrolled == 0 ? "Add Fingerprint" : "Add Another") {
                Task { await setup.enroll() }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!canEnroll)

            Fact(name: "Stored on the device",
                 value: "\(enrolled) fingerprint\(enrolled == 1 ? "" : "s")")
                .padding(.horizontal, 4)

            if enrolled > 0 {
                Text("Adding another finger needs a match from one already enrolled, "
                     + "so you will be asked to touch twice as many times.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var defaultSubtitle: String {
        enrolled == 0
            ? "The fingerprint is stored inside the sensor and never reaches your Mac."
            : "You already have one enrolled. Add another finger, or carry on."
    }
}

struct TestScreen: View {
    @EnvironmentObject private var setup: Setup

    private var templates: Int { setup.status?.templates ?? 0 }

    var body: some View {
        VStack(spacing: 22) {
            SensorArtwork(ring: setup.ring, progress: setup.progress)
            Title(text: setup.headline.isEmpty ? "Try It Once" : setup.headline,
                  subtitle: setup.detail.isEmpty
                    ? "Ask the device to sign something. This is the same request "
                        + "your Mac makes when it unlocks."
                    : setup.detail)

            Button("Request a Signature") {
                Task { await setup.testSignature() }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(setup.busy || templates == 0 || (setup.status?.lockout ?? 0) > 0)

            if templates == 0 {
                Text("Enroll a fingerprint first — there is nothing to match against.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if let status = setup.status, status.failures > 0 || status.lockout > 0 {
                VStack(spacing: 9) {
                    Fact(name: "Failed matches in a row", value: "\(status.failures) of 5",
                         warn: status.failures >= 3)
                    if status.lockout > 0 {
                        Fact(name: "Locked out", value: "\(status.lockout) s", warn: true)
                    }
                }
                .padding(.horizontal, 4)
            }
        }
    }
}

struct LoginScreen: View {
    @EnvironmentObject private var setup: Setup

    private var blocked: String? {
        if setup.status?.isBringup == true {
            return "This is a bringup image. It would let anyone in."
        }
        if !setup.pairing.driverIsDeskID {
            return setup.pairing.driver.isEmpty
                ? "macOS has not attached a driver to the card yet."
                : "Apple's PIV driver owns the card, and it always asks for a PIN. "
                    + (setup.pairing.driverInstalled
                        ? "Unplug and replug DeskID; if that does not change it, the board "
                            + "needs firmware that answers the DeskID AID."
                        : "Install the DeskID driver first.")
        }
        if setup.pairing.identityHash.isEmpty {
            return "macOS does not see an identity on the card yet."
        }
        if (setup.status?.templates ?? 0) == 0 {
            return "Enroll a fingerprint first — pairing itself needs a match."
        }
        return nil
    }

    var body: some View {
        VStack(spacing: 22) {
            SensorArtwork(ring: setup.ring, progress: setup.ring == .success ? 1 : 0)
            Title(text: setup.headline.isEmpty ? "Use It to Unlock Your Mac"
                                               : setup.headline,
                  subtitle: setup.detail.isEmpty
                    ? "Pairing tells macOS this card may authenticate you at the "
                        + "login window, the lock screen, and admin prompts."
                    : setup.detail)

            VStack(spacing: 9) {
                Fact(name: "Account", value: Pairing.user)
                Fact(name: "Driver",
                     value: setup.pairing.driverIsDeskID ? "DeskID"
                        : setup.pairing.driver.isEmpty ? "none" : "Apple PIV (asks for a PIN)",
                     warn: !setup.pairing.driverIsDeskID)
                Fact(name: "Card identity",
                     value: setup.pairing.identityHash.isEmpty
                        ? "not visible" : String(setup.pairing.identityHash.prefix(16)) + "…",
                     warn: setup.pairing.identityHash.isEmpty)
                Fact(name: "Paired", value: setup.paired ? "yes" : "no")
                Fact(name: "Enabled for login",
                     value: setup.pairing.loginEnabled ? "yes" : "no",
                     warn: !setup.pairing.loginEnabled)
                Fact(name: "FileVault preboot",
                     value: setup.pairing.fileVaultEnabled ? "card" : "password only",
                     warn: !setup.pairing.fileVaultEnabled)
            }
            .padding(.horizontal, 4)

            if let blocked {
                Warning(blocked)
            } else if setup.paired && !setup.pairing.loginEnabled {
                Warning("""
                    This Mac is paired with the card but has never been told \
                    the DeskID token class may authenticate anyone, so every \
                    prompt still asks for your password. Press Pair Again — it \
                    enables the class and re-pairs in one step.
                    """)
            } else if !setup.paired {
                Warning("""
                    Pairing asks the device to sign, so touch the sensor when \
                    the ring lights — right after the password dialog closes. \
                    You have about \(Int(Device.presenceTimeout)) seconds.
                    """)
            }
            if setup.pairing.soleAdministrator && !setup.paired {
                Warning("""
                    You are the only administrator on this Mac. Unplugging the \
                    token always restores password login, and FileVault preboot \
                    never uses the card, but a second admin account costs nothing.
                    """)
            }

            HStack(spacing: 10) {
                if !setup.pairing.driverInstalled {
                    Button("Install DeskID Driver") { Task { await setup.installDriver() } }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(setup.busy)
                }
                Button(setup.paired ? "Pair Again" : "Pair with This Mac") {
                    Task { await setup.pair() }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(setup.busy || blocked != nil)

                if setup.paired {
                    Button("Unpair") { Task { await setup.unpair() } }
                        .controlSize(.large)
                        .disabled(setup.busy)
                }
            }
        }
    }
}

struct DoneScreen: View {
    @EnvironmentObject private var setup: Setup

    var body: some View {
        VStack(spacing: 22) {
            SensorArtwork(ring: .success, progress: 1)
            Title(text: setup.paired ? "Ready" : "Set Up, Not Paired",
                  subtitle: setup.paired
                    ? "Where macOS asks who you are, it will now take DeskID."
                    : "The device works. You chose not to hand it your login, "
                        + "which you can do any time from the previous step.")

            VStack(alignment: .leading, spacing: 13) {
                Hint("touchid", "Touch the sensor as you sit down.",
                     "The ring is live before macOS asks anything. A match is held "
                     + "for \(Int(Device.earlyTouchWindow)) seconds and spent by the "
                     + "next prompt, so the prompt is answered the moment you submit it.")
                Hint("keyboard", "Then type any digits and press Return.",
                     "macOS draws a PIN field for every smart card and no public "
                     + "setting removes it. DeskID ignores what you type — your "
                     + "fingerprint is the secret.")
                Hint("bolt.horizontal", "Nothing held? Touch it then.",
                     "The ring starts breathing when a request is waiting, and gives "
                     + "up after \(Int(Device.presenceTimeout)) seconds without a match.")
                Hint("lock.open", "Unplug to get out.",
                     "That restores password login immediately. FileVault preboot "
                     + "always takes your password.")
            }
            .padding(.horizontal, 2)
        }
    }
}

/// One piece of daily advice: symbol, the instruction, then the why.
struct Hint: View {
    let symbol: String
    let instruction: String
    let reason: String

    init(_ symbol: String, _ instruction: String, _ reason: String) {
        self.symbol = symbol
        self.instruction = instruction
        self.reason = reason
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 16))
                .foregroundStyle(Color.accentColor)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(instruction).font(.callout).fontWeight(.medium)
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - Shell

struct RootView: View {
    @EnvironmentObject private var setup: Setup
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var forward = true

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 18) {
                    screen
                        .id(setup.step)
                        .transition(slide)
                    if let failure = setup.failure {
                        Warning(failure)
                    }
                }
                .padding(.horizontal, 34)
                .padding(.top, 30)
                .padding(.bottom, 24)
                .frame(maxWidth: .infinity)
            }
            footer
        }
        .frame(width: 460, height: 640)
        .task(id: setup.step) { await watchForDevice() }
    }

    @ViewBuilder
    private var screen: some View {
        switch setup.step {
        case .connect: ConnectScreen()
        case .fingerprint: FingerprintScreen()
        case .test: TestScreen()
        case .login: LoginScreen()
        case .done: DoneScreen()
        }
    }

    private var footer: some View {
        HStack {
            Button("Back") { back() }
                .disabled(setup.step == .connect || setup.busy)
                .opacity(setup.step == .connect ? 0 : 1)

            Spacer()
            StepDots(step: setup.step)
            Spacer()

            Button(setup.step == .done ? "Finish" : "Continue") { next() }
                .keyboardShortcut(.defaultAction)
                .disabled(!canContinue)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 14)
        .background(.bar)
    }

    private var canContinue: Bool {
        if setup.busy { return false }
        switch setup.step {
        case .connect: return setup.connected
        default: return true
        }
    }

    private func next() {
        guard let step = Step(rawValue: setup.step.rawValue + 1) else {
            NSApplication.shared.terminate(nil)
            return
        }
        forward = true
        withAnimation(motion) { setup.go(to: step) }
    }

    private func back() {
        guard let step = Step(rawValue: setup.step.rawValue - 1) else { return }
        forward = false
        withAnimation(motion) { setup.go(to: step) }
    }

    private var motion: Animation {
        reduceMotion ? .easeOut(duration: 0.2) : .spring(response: 0.4, dampingFraction: 1)
    }

    /// Screens enter from the side you are heading toward and leave the way
    /// they came, so Back visibly reverses Continue. Reduced motion cross-fades.
    private var slide: AnyTransition {
        reduceMotion ? .opacity : .asymmetric(
            insertion: .move(edge: forward ? .trailing : .leading).combined(with: .opacity),
            removal: .move(edge: forward ? .leading : .trailing).combined(with: .opacity))
    }

    /// Poll for as long as the first screen is up. Stopping at the first
    /// answer would freeze the panel the moment the token is unplugged, and
    /// this screen promises that it updates on its own.
    private func watchForDevice() async {
        guard setup.step == .connect else { return }
        while !Task.isCancelled {
            await setup.refresh()
            try? await Task.sleep(nanoseconds: 1_500_000_000)
        }
    }
}

/// Unbundled scripts get no menu bar, so ⌘Q would not work without this.
final class Delegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

func installMenu(_ application: NSApplication) {
    let bar = NSMenu()
    let appItem = NSMenuItem()
    let appMenu = NSMenu()
    appMenu.addItem(withTitle: "Quit DeskID Setup", action: #selector(NSApplication.terminate(_:)),
                    keyEquivalent: "q")
    appItem.submenu = appMenu
    bar.addItem(appItem)
    application.mainMenu = bar
}

// MARK: - Persistent token (E1a)

/// `--persistent` publishes the board's certificate as a persistent token,
/// the class SecurityAgent handles without its smart-card PIN panel. Only the
/// container app may register token configurations, which is why this lives
/// here and not in a script. The signature itself still comes from the board.
if CommandLine.arguments.contains("--persistent") {
    let driverID = "dev.deskid.setup.persistent"
    let done = DispatchSemaphore(value: 0)
    var result: Result<Data, Error> = .failure(DeviceError.noReader)
    Task {
        do { result = .success(try await Device.certificate()) } catch { result = .failure(error) }
        done.signal()
    }
    done.wait()
    let der: Data
    do { der = try result.get() } catch { print("failed: \(error.localizedDescription)"); exit(1) }

    guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
        print("failed: the board's certificate does not parse"); exit(1)
    }
    guard let driver = TKTokenDriver.Configuration.driverConfigurations[driverID] else {
        print("failed: no driver configuration for \(driverID) — run tools/deskid-setup --install first")
        exit(1)
    }
    var hasher = SHA256(); hasher.update(data: der)
    let instanceID = hasher.finalize().prefix(16).map { String(format: "%02X", $0) }.joined()
    let configuration = driver.addTokenConfiguration(for: instanceID)
    let certificateItem = TKTokenKeychainCertificate(certificate: certificate, objectID: "5FC105")!
    let keyItem = TKTokenKeychainKey(certificate: certificate, objectID: "9A")!
    keyItem.canSign = true
    keyItem.canDecrypt = false
    keyItem.canPerformKeyExchange = false
    keyItem.isSuitableForLogin = true
    keyItem.constraints = [TKTokenOperation.signData.rawValue as NSNumber: true]
    configuration.keychainItems = [certificateItem, keyItem]
    print("configured \(driverID):\(instanceID)")
    print("next: security list-smartcards; sc_auth identities; then pair")
    exit(0)
}

/// `--forget-persistent` removes every persistent-token configuration this
/// app registered, returning macOS to the smart-card driver alone.
if CommandLine.arguments.contains("--forget-persistent") {
    let driverID = "dev.deskid.setup.persistent"
    guard let driver = TKTokenDriver.Configuration.driverConfigurations[driverID] else {
        print("no driver configuration for \(driverID); nothing to forget"); exit(0)
    }
    for instanceID in driver.tokenConfigurations.keys {
        driver.removeTokenConfiguration(for: instanceID)
        print("forgot \(driverID):\(instanceID)")
    }
    exit(0)
}

/// `--pinpad` asks CryptoTokenKit — not PC/SC — whether this reader can
/// verify a PIN on its own pad, and if so runs one VERIFY through it. This is
/// the exact call the system makes for a pad-capable reader, so its answer
/// is SecurityAgent's answer.
if CommandLine.arguments.contains("--pinpad") {
    let done = DispatchSemaphore(value: 0)
    Task {
        defer { done.signal() }
        do {
            guard let manager = TKSmartCardSlotManager.default,
                  let name = Device.readerName,
                  let slot = await manager.getSlot(withName: name),
                  let card = slot.makeSmartCard()
            else { print("no DeskID reader"); return }
            guard try await card.beginSession() else { print("card busy"); return }
            defer { card.endSession() }
            _ = try await card.transmit(APDU.selectDeskID)

            // Must mirror TokenSession.beginAuthFor in tools/deskid_token.swift,
            // or this measures a pad request SecurityAgent will never make.
            let format = TKSmartCardPINFormat()
            format.charset = .numeric
            format.encoding = .ascii
            format.minPINLength = 0
            format.maxPINLength = 8
            format.pinBlockByteLength = 8
            format.pinJustification = .left
            let template = Data([0x00, 0x20, 0x00, 0x80, 0x08,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
            guard let interaction = card.userInteractionForSecurePINVerification(
                format, apdu: template, pinByteOffset: 5)
            else { print("CryptoTokenKit: reader has no usable PIN pad"); return }
            interaction.initialTimeout = 30
            interaction.interactionTimeout = 30
            print("CryptoTokenKit: pad available — touch the sensor")
            let started = Date()
            try await interaction.run()
            print(String(format: "pad VERIFY answered %04X in %.1f s",
                         interaction.resultSW, Date().timeIntervalSince(started)))
        } catch {
            print("failed: \(error.localizedDescription)")
        }
    }
    done.wait()
    exit(0)
}

/// `--certificate` writes the board's slot-9A certificate to stdout as DER.
/// It reads the reader directly rather than the published token, so enrolling
/// the PAM module never depends on the CryptoTokenKit stack it exists to
/// stand beside.
if CommandLine.arguments.contains("--certificate") {
    let done = DispatchSemaphore(value: 0)
    var result: Result<Data, Error> = .failure(DeviceError.noReader)
    Task {
        do { result = .success(try await Device.certificate()) } catch { result = .failure(error) }
        done.signal()
    }
    done.wait()
    do { FileHandle.standardOutput.write(try result.get()) }
    catch {
        FileHandle.standardError.write(Data("failed: \(error.localizedDescription)\n".utf8))
        exit(1)
    }
    exit(0)
}

// The assist modes (--unlock, --set-password, --install-unlock, ...) live in
// tools/deskid_assist.swift; every one of them exits.
Assist.runIfRequested()

// MARK: - Self-test

/// `--check` exercises the parsing that stands between the board and the
/// screen, against a status object recorded from a real DeskID, then exits.
if CommandLine.arguments.contains("--check") {
    let recorded = Data([
        0x53, 0x36, 0x01, 0x05, 0x30, 0x2E, 0x31, 0x2E, 0x30, 0x02, 0x01, 0x01, 0x03, 0x04, 0x00,
        0x00, 0x17, 0xEA, 0x04, 0x01, 0x01, 0x05, 0x04, 0x00, 0x05, 0x77, 0xA8, 0x06, 0x01, 0x01,
        0x07, 0x01, 0x09, 0x08, 0x01, 0x01, 0x09, 0x01, 0x00, 0x0A, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x0B, 0x04, 0x00, 0x00, 0x00, 0x01, 0x0C, 0x01, 0x00, 0xFE, 0x00,
    ])
    let status = DeviceStatus(fields: tlv(tlv(recorded)[0x53] ?? Data()))
    let long = tlv(Data([0x70, 0x81, 0x03, 0x01, 0x02, 0x03]))[0x70]
    let hashes = Pairing.hashes(in: "Unpaired identities:\n"
        + "5F1A306E3B723317023FA764043C23A8914C4221\tCertificate For PIV (DeskID 001)\n")
    let ok = status.firmware == "0.1.0" && status.variant == 1 && status.sensorReady
        && status.credential && status.failures == 0 && status.lockout == 0 && status.templates == 1
        && long == Data([1, 2, 3])
        && hashes == ["5F1A306E3B723317023FA764043C23A8914C4221"]
        && APDU.generalAuthenticate(Data(count: 32)).count == 44
        && APDU.getData(APDU.statusTag) == Data([0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03,
                                                 0x5F, 0xFF, 0x01, 0x00])
        && Assist.selfCheck()
    print(ok ? "ok" : "FAILED: \(status) \(String(describing: long)) \(hashes)")
    exit(ok ? 0 : 1)
}

// MARK: - Launch

let application = NSApplication.shared
let delegate = Delegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
installMenu(application)

let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 460, height: 640),
    styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
    backing: .buffered,
    defer: false)
window.title = "DeskID Setup"
window.titlebarAppearsTransparent = true
window.isMovableByWindowBackground = true
// Top-level script code already runs on the main thread; the compiler
// cannot see that on its own.
let setup = MainActor.assumeIsolated { Setup() }
window.contentView = NSHostingView(rootView: RootView().environmentObject(setup))
window.center()
window.makeKeyAndOrderFront(nil)
application.activate(ignoringOtherApps: true)
application.run()
