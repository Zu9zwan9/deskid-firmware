// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

// DeskID assist — the part that removes the typing.
//
// Compiled into "DeskID Setup.app" alongside tools/deskid_setup.swift and
// reached through its own command-line modes. It is a separate file because it
// is the only component that synthesises keystrokes, and that deserves to be
// readable end to end without scrolling past a setup wizard.
//
// ## Why this exists
//
// macOS draws a PIN field for every paired smart card, at the lock screen and
// in `pam_smartcard`. Four separate attempts to remove it — a
// `constraint = true` token, a persistent token, a reader-side PIN pad, and
// every published smart-card setting — all failed. The field is
// SecurityAgent's own UI and no public API touches it. So the last honest
// move is to fill it in.
//
// ## The lock screen is deliberately not here
//
// It was, and it was removed on 2026-09-02 after two measurements.
//
// It could not work: SecurityAgent holds the card while the lock screen is up,
// `TKSmartCard.beginSession` is exclusive, so this agent could neither ask the
// board to watch its ring nor find out that a touch had landed. The board's
// status showed `ring armed by host: no` throughout.
//
// And it should not: typing into a lock screen means competing with the person
// standing at it. During the same session the Mac reached a state where
// neither a touch nor the password got in.
//
// The board arms itself now instead. A fresh applet SELECT is macOS saying it
// cares about this card, and at the lock screen that lands when the screen
// wakes — so the ring is watched for 20 s from exactly the moment someone
// walks up (`kArmOnSelectSeconds`). Touch on arrival, type any digits, and the
// signature is answered from the touch already in hand. No permission, no
// injection, no process in the way.
//
// ## What is left: the fields the board cannot sign for
//
// Website password fields, keychain prompts and authorisation sheets are
// LocalAuthentication and password UI, not smart-card UI: nothing DeskID can
// sign satisfies them. Filling those in means holding the string they want, so
// this is **off by default** and stored deliberately, with two safeguards:
//
//   - `kSecAttrAccessibleWhenUnlocked`, not `AfterFirstUnlock`. The secret is
//     unreadable while the screen is locked, which is exactly when an
//     unattended Mac is at risk. Nothing here runs while locked, so nothing is
//     lost by locking it away harder.
//   - It is only ever typed into a field macOS has marked secure
//     (`AXSecureTextField`). A focused ordinary text field gets nothing, so a
//     stray touch cannot spray a password into a chat window.
//
// ## The gesture
//
// One touch. The board holds a match for 30 s (`kEarlyTouchValidMilliseconds`
// in src/main.cpp) and reports it in status tag `0x12`; this polls for that and
// acts once per touch. At the lock screen the same held match then answers
// SecurityAgent's signature request with no wait, which is the whole point of
// touching before macOS asks.

import AppKit
import ApplicationServices
import Foundation

enum Assist {
    static let keychainService = "dev.deskid.assist.password"
    static let launchAgentLabel = "dev.deskid.assist"
    static let pollSeconds = 0.4
    /// Long enough for SecurityAgent to take the field, ask the token, and for
    /// the board to answer from the touch already in hand.
    static let settleSeconds = 6.0
    /// Re-armed at half this interval, so the window never lapses mid-login.
    /// The board caps it at 120 s regardless.
    static let ringArmSeconds = 60.0

    // MARK: - Keychain

    /// `WhenUnlocked`, deliberately: unreadable while the screen is locked.
    static func storePassword(_ password: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
        ]
        SecItemDelete(query as CFDictionary)
        guard !password.isEmpty else { return true }
        var item = query
        item[kSecValueData as String] = Data(password.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
    }

    static func storedPassword() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - What is on screen

    static var screenLocked: Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return session["CGSSessionScreenIsLocked"] as? Bool == true
    }

    /// True only for a field macOS itself marks secure. An ordinary focused
    /// text field must never receive the stored password.
    static var secureFieldFocused: Bool {
        var focused: CFTypeRef?
        guard AXUIElementCopyAttributeValue(AXUIElementCreateSystemWide(),
                                            kAXFocusedUIElementAttribute as CFString,
                                            &focused) == .success,
              CFGetTypeID(focused) == AXUIElementGetTypeID()
        else { return false }
        let element = focused as! AXUIElement
        for attribute in [kAXSubroleAttribute, kAXRoleAttribute] {
            var value: CFTypeRef?
            if AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success,
               (value as? String) == (kAXSecureTextFieldSubrole as String) {
                return true
            }
        }
        return false
    }

    // MARK: - Typing

    static func type(_ text: String, thenReturn: Bool = true) {
        guard let source = CGEventSource(stateID: .combinedSessionState) else { return }
        // A modifier still held from the lock hotkey turns the characters into
        // control codes and the field stays silently empty.
        if let clear = CGEvent(source: source) {
            clear.type = .flagsChanged
            clear.flags = []
            clear.post(tap: .cghidEventTap)
        }
        for character in Array(text.utf16) {
            for down in [true, false] {
                guard let event = CGEvent(keyboardEventSource: source, virtualKey: 0,
                                          keyDown: down) else { continue }
                var unit = character
                event.keyboardSetUnicodeString(stringLength: 1, unicodeString: &unit)
                event.post(tap: .cghidEventTap)
            }
        }
        guard thenReturn else { return }
        for down in [true, false] {
            CGEvent(keyboardEventSource: source, virtualKey: 0x24, keyDown: down)?
                .post(tap: .cghidEventTap)
        }
    }

    // MARK: - The loop

    /// The board only spends power watching the ring while something is
    /// waiting for it, so this is the question it is armed against.
    static var wantsATouch: Bool { secureFieldFocused }

    /// What a touch should do right now, or nil for "nothing here wants one".
    /// A touch with no destination is left unspent so it can still answer the
    /// signature the board is really there for.
    static func actionForCurrentScreen() -> String? {
        // Never while locked: see the file comment. The lock screen is the
        // board's own job now.
        guard !screenLocked, secureFieldFocused else { return nil }
        return storedPassword()
    }

    private static func daemon() -> Never {
        // Under launchd stdout is a file, so it is fully buffered and a log
        // that only appears when the agent dies is not a log.
        setvbuf(stdout, nil, _IONBF, 0)
        // Ask once. Exiting when the answer is "not yet" would be wrong here:
        // launchd keeps this agent alive, so it would respawn and re-prompt in
        // a loop. It waits instead, and the timer re-checks every pass — which
        // is also what makes revoking the permission take effect immediately.
        if !AXIsProcessTrustedWithOptions(
            [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary) {
            print("Waiting for Accessibility permission "
                  + "(System Settings > Privacy & Security > Accessibility).")
        }
        print("DeskID assist running. Touch the sensor at a password field.")

        // One action per touch: re-arm only once the board reports the match
        // has been spent or expired, so a 30 s window cannot type twice.
        final class State {
            var armed = true
            var busy = false
            var quietUntil = Date.distantPast
            var nextRingArm = Date.distantPast
        }
        let state = State()

        Timer.scheduledTimer(withTimeInterval: pollSeconds, repeats: true) { _ in
            guard AXIsProcessTrusted(), !state.busy, Date() > state.quietUntil else { return }
            state.busy = true
            Task { @MainActor in
                defer { state.busy = false }
                // SecurityAgent owns the card while it signs, so a refused
                // session is the normal case then rather than an error.
                // The board watches its own sensor for free when the wake
                // line works, and by spending an image capture per poll when
                // it does not — so it is told when that is worth doing rather
                // than doing it always. Here, that is exactly when somewhere
                // on screen is waiting to be authenticated.
                let wanted = wantsATouch
                let arm = wanted && Date() >= state.nextRingArm
                guard let status = try? await Device.withCard({ session -> DeviceStatus in
                    if arm { try? await session.armRing(UInt8(ringArmSeconds)) }
                    return try await session.status()
                }) else { return }
                if arm { state.nextRingArm = Date().addingTimeInterval(ringArmSeconds / 2) }
                guard status.touchHeldSeconds > 0 else { state.armed = true; return }
                guard state.armed, let text = actionForCurrentScreen() else { return }
                state.armed = false
                state.quietUntil = Date().addingTimeInterval(settleSeconds)
                type(text)
            }
        }
        RunLoop.main.run()
        exit(0)
    }

    // MARK: - Login item

    private static var agentPlistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(launchAgentLabel).plist")
    }

    private static func installAgent() -> Never {
        let binary = "/Applications/DeskID Setup.app/Contents/MacOS/DeskID Setup"
        guard FileManager.default.isExecutableFile(atPath: binary) else {
            print("Run 'tools/deskid-setup --install' first — the agent runs the copy in /Applications.")
            exit(1)
        }
        // launchd swallows a login agent's output, and "is it running and does
        // it have permission" is the only question anyone ever asks about one.
        let log = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/\(launchAgentLabel).log").path
        let plist: [String: Any] = [
            "Label": launchAgentLabel,
            "ProgramArguments": [binary, "--unlock"],
            "RunAtLoad": true,
            "KeepAlive": true,
            "StandardOutPath": log,
            "StandardErrorPath": log,
        ]
        do {
            try FileManager.default.createDirectory(
                at: agentPlistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try (try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0))
                .write(to: agentPlistURL)
        } catch {
            print("could not write \(agentPlistURL.path): \(error.localizedDescription)")
            exit(1)
        }
        _ = shell(["launchctl", "bootout", "gui/\(getuid())/\(launchAgentLabel)"])
        let loaded = shell(["launchctl", "bootstrap", "gui/\(getuid())", agentPlistURL.path])
        print(loaded ? "assist installed and running" : "wrote \(agentPlistURL.path); launchctl refused")
        exit(loaded ? 0 : 1)
    }

    private static func uninstallAgent() -> Never {
        _ = shell(["launchctl", "bootout", "gui/\(getuid())/\(launchAgentLabel)"])
        try? FileManager.default.removeItem(at: agentPlistURL)
        print("assist removed")
        exit(0)
    }

    @discardableResult
    private static func shell(_ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = Array(arguments.dropFirst())
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    // MARK: - Entry

    /// Called first from the app's top level. Every mode here exits.
    static func runIfRequested() {
        let arguments = CommandLine.arguments
        if arguments.contains("--unlock") { daemon() }
        if arguments.contains("--install-unlock") { installAgent() }
        if arguments.contains("--uninstall-unlock") { uninstallAgent() }
        if arguments.contains("--forget-password") {
            print(storePassword("") ? "password forgotten" : "keychain refused")
            exit(0)
        }
        if arguments.contains("--set-password") {
            // getpass, not an argument: a password on the command line is in
            // `ps` output and in shell history.
            guard let entered = getpass("Login password (typed only into secure fields): ")
                .map({ String(cString: $0) }), !entered.isEmpty else {
                print("nothing entered; unchanged")
                exit(1)
            }
            print(storePassword(entered) ? "stored" : "keychain refused")
            exit(0)
        }
    }

    /// Exercised by `--check`. Keeps the two rules that decide where a touch
    /// goes honest: nothing is ever typed at the lock screen, and a secret is
    /// only ever offered to a field macOS itself marked secure.
    static func selfCheck() -> Bool {
        (screenLocked ? actionForCurrentScreen() == nil : true)
            && (!secureFieldFocused ? actionForCurrentScreen() == nil : true)
    }
}
