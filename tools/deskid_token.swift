// The DeskID CryptoTokenKit smart-card token.
//
// This is the piece that makes DeskID a login method instead of a smart card
// that happens to be plugged in. macOS loads it as an app extension inside
// "DeskID Setup.app" (see tools/deskid-setup), hands it the card whenever a
// reader answers the DeskID AID, and from then on every place macOS wants a
// signature — the login window, the lock screen, sudo, keychain — comes here.
//
// Two decisions carry the whole product:
//
//   1. The signing key is published with the constraint `true`, which tells
//      macOS the operation is always allowed. No PIN is defined, so no PIN
//      field is drawn. Apple's built-in PIV driver hard-codes "PIN required"
//      for slot 9A, which is why it can never give a PIN-less login.
//   2. `sign` forwards the digest to the board as GENERAL AUTHENTICATE and
//      blocks until the board answers. The board only answers after a live
//      fingerprint match, so the fingerprint is the secret and the extension
//      holds nothing worth stealing.

import CryptoTokenKit
import CryptoKit
import Security

enum APDU {
    static let deskIDAID = Data([0xF0, 0x44, 0x65, 0x73, 0x6B, 0x49, 0x44])  // F0 "DeskID"
    static let pivAID = Data([0xA0, 0x00, 0x00, 0x03, 0x08])

    static func select(_ aid: Data) -> Data {
        Data([0x00, 0xA4, 0x04, 0x00, UInt8(aid.count)]) + aid
    }

    static let certificate = Data([0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00])

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

func failure(_ code: TKError.Code, _ text: String) -> NSError {
    NSError(domain: TKErrorDomain, code: code.rawValue,
            userInfo: [NSLocalizedDescriptionKey: text])
}

extension TKSmartCard {
    /// One APDU through CryptoTokenKit's synchronous, case-aware transmit,
    /// which drains `61xx` continuations itself. Returns data and status word.
    func send(_ apdu: Data) throws -> (data: Data, status: UInt16) {
        let bytes = [UInt8](apdu)
        let body = bytes.count > 5 ? Data(bytes[5..<5 + Int(bytes[4])]) : nil
        let wantsResponse = bytes.count == 5 || bytes.count > 5 + Int(bytes[4])
        let (sw, response) = try send(ins: bytes[1], p1: bytes[2], p2: bytes[3],
                                      data: body, le: wantsResponse ? 0 : nil)
        return (response, sw)
    }
}

final class TokenDriver: TKSmartCardTokenDriver, TKSmartCardTokenDriverDelegate {
    override init() {
        super.init()
        delegate = self
    }

    func tokenDriver(_ driver: TKSmartCardTokenDriver, createTokenFor smartCard: TKSmartCard,
                     aid: Data?) throws -> TKSmartCardToken {
        try Token(smartCard: smartCard, aid: aid, driver: driver)
    }
}

final class Token: TKSmartCardToken, TKTokenDelegate {
    static let keyID = "9A"
    static let certificateID = "5FC105"

    init(smartCard: TKSmartCard, aid: Data?, driver: TKSmartCardTokenDriver) throws {
        // The system has already selected `aid` for us; read the certificate
        // it protects. Its hash is also the token instance ID, so the same
        // card is the same token on every insertion.
        let (object, status) = try smartCard.send(APDU.certificate)
        guard status == 0x9000,
              let der = tlv(tlv(object)[0x53] ?? Data())[0x70],
              let certificate = SecCertificateCreateWithData(nil, der as CFData)
        else { throw failure(.objectNotFound, "the card has no certificate") }

        let instanceID = SHA256.hash(data: der).prefix(16)
            .map { String(format: "%02X", $0) }.joined()
        super.init(smartCard: smartCard, aid: aid, instanceID: instanceID, tokenDriver: driver)
        delegate = self

        let certificateItem = TKTokenKeychainCertificate(certificate: certificate,
                                                         objectID: Self.certificateID)!
        let keyItem = TKTokenKeychainKey(certificate: certificate, objectID: Self.keyID)!
        keyItem.canSign = true
        keyItem.canDecrypt = false
        keyItem.canPerformKeyExchange = false
        keyItem.isSuitableForLogin = true
        // `true` means "always allowed", so `beginAuthFor` is never called and
        // SecurityAgent draws its own text field. That field costs one Return
        // press, and three independent measurements now say it cannot be
        // removed with public APIs:
        //
        //   Q4/Q5 (2026-09-02) — neither the
        //     stock PIV driver nor a persistent token avoids the panel.
        //   Pad path (2026-09-02, after `enable_for_login` was finally set) —
        //     `--pinpad` reports "pad available" and a secure VERIFY reaches the
        //     applet through PC_to_RDR_Secure, so the reader's pad genuinely
        //     works. Declaring a constraint here does route signing through
        //     `beginAuthFor`, and the lock screen still drew its own field and
        //     still wanted Return. SecurityAgent does not offer the pad.
        //
        // An earlier note blamed that last result on the constraint and was
        // written before `enable_for_login` had ever run, so it measured a
        // token SecurityAgent was ignoring entirely. Re-measured; same answer,
        // for a real reason this time.
        //
        // So `true` wins on the merits, not by default: the constraint version
        // buys nothing at the lock screen and adds a PIN prompt to keychain and
        // sudo, which `true` passes straight through to the fingerprint.
        keyItem.constraints = [TKTokenOperation.signData.rawValue as NSNumber: true]
        keychainContents?.fill(with: [certificateItem, keyItem])
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        TokenSession(token: self)
    }
}

final class TokenSession: TKSmartCardTokenSession, TKTokenSessionDelegate {
    override init(token: TKToken) {
        super.init(token: token)
        delegate = self
    }

    /// macOS authenticates the user by sending VERIFY, and prefers to let a
    /// reader with a PIN pad collect the PIN itself. DeskID's reader declares
    /// a pad (`bPINSupport` in the CCID descriptor) whose "keypad" is the
    /// fingerprint ring: the board fills in nothing, waits for a match, and
    /// answers `9000`. Hosts without pad support fall back to typing digits
    /// into this template — the applet ignores them and gates on the finger
    /// just the same. Either way the verified state is spent by the very
    /// next signature, so a login is exactly one touch.
    func tokenSession(_ session: TKTokenSession, beginAuthFor operation: TKTokenOperation,
                      constraint: Any) throws -> TKTokenAuthOperation {
        let auth = TKTokenSmartCardPINAuthOperation()
        auth.apduTemplate = Data([0x00, 0x20, 0x00, 0x80, 0x08,
                                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        auth.pinByteOffset = 5
        let format = TKSmartCardPINFormat()
        format.charset = .numeric
        format.encoding = .ascii
        // Zero, not six: the digits carry nothing, so any minimum the system
        // enforces is a minimum number of meaningless keystrokes. Where the
        // panel honours the token's format, Return on an empty field is the
        // whole PIN step.
        format.minPINLength = 0
        format.maxPINLength = 8
        format.pinBlockByteLength = 8
        format.pinJustification = .left
        auth.pinFormat = format
        auth.smartCard = try getSmartCard()
        return auth
    }

    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation,
                      keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) -> Bool {
        operation == .signData
            && (algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA256)
                || algorithm.isAlgorithm(.ecdsaSignatureMessageX962SHA256))
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: Any,
                      algorithm: TKTokenKeyAlgorithm) throws -> Data {
        let digest = algorithm.isAlgorithm(.ecdsaSignatureMessageX962SHA256)
            ? Data(SHA256.hash(data: dataToSign)) : dataToSign
        guard digest.count == 32 else { throw failure(.badParameter, "not a SHA-256 digest") }

        // The system hands us the card with our AID already selected and an
        // exclusive session open. This blocks for up to the board's presence
        // window (30 s) while the ring waits for a finger; CCID time
        // extensions keep the transport alive.
        let card = try getSmartCard()
        let (data, status) = try card.send(APDU.generalAuthenticate(digest))
        switch status {
        case 0x9000:
            guard let signature = tlv(tlv(data)[0x7C] ?? Data())[0x82] else {
                throw failure(.corruptedData, "no signature in the response")
            }
            return signature
        case 0x6982: throw failure(.canceledByUser, "no fingerprint match")
        case 0x6983: throw failure(.authenticationFailed, "fingerprint sensor locked out")
        default: throw failure(.communicationError, String(format: "card answered %04X", status))
        }
    }
}
