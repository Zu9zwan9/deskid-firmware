// Answers one question about a connected PIV token: does macOS demand a PIN
// before it will sign with the token's key?
//
//     swift tools/pin_probe.swift
//     swift tools/pin_probe.swift --allow-ui
//
// The default run forbids authentication UI, so a token whose key is behind a
// PIN fails with errSecInteractionNotAllowed instead of opening a dialog. That
// makes the probe safe to run unattended and its result unambiguous: a
// signature means no PIN stands between macOS and the card, and DeskID's
// fingerprint gate is the only thing guarding the key.
//
// Nothing here modifies the system. It does not pair, and it does not touch
// login policy.

import Foundation
import LocalAuthentication
import Security

let allowInteraction = CommandLine.arguments.contains("--allow-ui")

func message(_ error: Unmanaged<CFError>?) -> String {
    guard let error = error?.takeRetainedValue() else {
        return "unknown error"
    }
    return "\(CFErrorGetCode(error)): \(CFErrorCopyDescription(error) as String? ?? "")"
}

func verdict(_ code: Int) -> String {
    switch code {
    case Int(LAError.notInteractive.rawValue), Int(errSecInteractionNotAllowed):
        return "PIN REQUIRED — macOS wanted to prompt before signing"
    case Int(LAError.userFallback.rawValue), Int(errSecAuthFailed):
        return "PIN REQUIRED — macOS refused the operation without authentication"
    case Int(LAError.userCancel.rawValue), Int(errSecUserCanceled):
        return "cancelled at the prompt, so a prompt exists: PIN REQUIRED"
    default:
        return "signing failed for an unrelated reason"
    }
}

let context = LAContext()
context.interactionNotAllowed = !allowInteraction

let query: [String: Any] = [
    kSecClass as String: kSecClassIdentity,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnRef as String: true,
    kSecUseAuthenticationContext as String: context,
]

var matches: CFTypeRef?
let searchStatus = SecItemCopyMatching(query as CFDictionary, &matches)
guard searchStatus == errSecSuccess, let identities = matches as? [SecIdentity] else {
    print("no identities available (OSStatus \(searchStatus)) — is the token connected?")
    exit(1)
}

var probed = 0
var failures = 0

for identity in identities {
    var key: SecKey?
    guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else {
        continue
    }
    let attributes = SecKeyCopyAttributes(key) as? [String: Any] ?? [:]
    guard let tokenIdentifier = attributes[kSecAttrTokenID as String] as? String else {
        continue
    }

    var certificate: SecCertificate?
    SecIdentityCopyCertificate(identity, &certificate)
    let subject = certificate.flatMap { SecCertificateCopySubjectSummary($0) as String? }

    probed += 1
    print("token   \(tokenIdentifier)")
    print("subject \(subject ?? "(unnamed)")")
    print("ui      \(allowInteraction ? "allowed" : "forbidden")")

    let digest = Data((0..<32).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
    var error: Unmanaged<CFError>?
    let started = Date()
    let signature = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256,
                                          digest as CFData, &error)
    let elapsed = Date().timeIntervalSince(started)

    guard let signature else {
        failures += 1
        let raw = error?.takeUnretainedValue()
        let code = raw.map { Int(CFErrorGetCode($0)) } ?? 0
        print("result  \(verdict(code))")
        print("detail  \(message(error))")
        if !allowInteraction {
            print("next    rerun with --allow-ui to see the prompt. DeskID's applet takes any")
            print("        6-8 digit PIN once the fingerprint gate is satisfied")
        }
        print("")
        continue
    }

    print("result  NO PIN — the card signed in \(String(format: "%.2f", elapsed)) s")
    if let certificate, let publicKey = SecCertificateCopyKey(certificate) {
        var verifyError: Unmanaged<CFError>?
        let valid = SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256,
                                          digest as CFData, signature, &verifyError)
        if valid {
            print("detail  signature verifies against the token certificate")
        } else {
            failures += 1
            print("detail  signature DOES NOT verify: \(message(verifyError))")
        }
    }
    if elapsed < 1.0 {
        print("note    signed with no perceptible delay — a sensor build would have waited")
    }
    print("")
}

if probed == 0 {
    print("no smart-card identities found — `sc_auth identities` should list one")
    exit(1)
}
exit(failures == 0 ? 0 : 2)
