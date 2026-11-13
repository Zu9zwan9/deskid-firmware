# Replacing Touch ID with DeskID: what macOS allows

## Summary

As of macOS 27.0.1 (12 November 2026), a third-party sensor cannot feed Apple's
Secure Enclave. Apple pairs its own
sensor to the enclave with a key set at the factory and encrypts that link
([Touch ID and the Secure Enclave](https://support.apple.com/en-me/guide/security/sec067eb0c9e/web)).
The [Secure Enclave page](https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web)
describes no interface for outside hardware, and LocalAuthentication, the API
apps call to show the Touch ID sheet, has no provider side. DeskID cannot
appear as Touch ID.

macOS supports a second way to authenticate a person: a smart card. Apple
lists where it works: the login window, the Lock
Screen, authorization dialogs, SSH, Safari, and through PAM `sudo`, `su` and
`login` ([Supported smart card functions on Mac](https://support.apple.com/guide/deployment/depc47f60521/web)).
DeskID targets these surfaces and already is a smart card.

## Surface by surface

"Bench" marks a claim that needs a measurement on a board.

| Where | Touch ID | DeskID today | To close the gap |
|---|---|---|---|
| Lock Screen | Touch | Works. macOS draws a PIN field; any digits, then the ring. Touch first makes it 0.2 s | Nothing removes Apple's field |
| Login after restart | Password first, by design | Card logs in; the disk and keychain still want the password | Gap A, slot 9D |
| System dialogs (Settings padlock, installers) | Touch | Supported for a paired card, with the PIN field | Bench: confirm on 27.0.1 with the DeskID driver |
| `sudo` | `pam_tid` | `pam_smartcard`, PIN field in Terminal | Gap B, `pam_deskid` |
| SSH, Safari client certificates | Not offered | Works, and is more than Touch ID does | None |
| Apple Pay, App Store, Passwords and passkey AutoFill, apps that call LocalAuthentication | Touch | Not possible | None. State this in product copy |
| Privacy prompts (camera, microphone, files) | A click, no authentication | Same | None needed |

## Gap A. Slot 9D

Apple: "For login, the Key Management key (9d) is used to unlock the encrypted
volume and to unlock the user's Keychain", and a card without an encryption key
"causes repeated keychain prompts"
([same page](https://support.apple.com/guide/deployment/depc47f60521/web),
[SmartCardServices(7)](https://keith.github.io/xcode-man-pages/SmartCardServices.7.html)).
Slot 9D is standard PIV and the largest step toward parity. The firmware
implements it (steps 1 to 3 below). The tools in steps 4 to 6 do not use it
yet.

Plan, test first:

1. `lib/deskid_core`: a slot argument on `PivCredential`; `GET DATA` and
   `PUT DATA` for `5FC10B`; `GENERATE ASYMMETRIC KEY PAIR` with P2 `9D`;
   `GENERAL AUTHENTICATE` P2 `9D` taking tag `85` (the peer's point) and
   returning the shared X coordinate in tag `82`. Same presence gate as a
   signature. Early touch may spend on it, because it is on the login path.
2. `test/test_piv`: the gate, the encodings, a rejected off-curve
   point, and one published P-256 ECDH vector through a software credential.
3. `src/main.cpp`: a second PSA key with `PSA_KEY_USAGE_DERIVE` and
   `PSA_ALG_ECDH`, `psa_raw_key_agreement`, NVS entries beside the existing
   pair, written as one blob so a power cut cannot split key from certificate.
4. `tools/provision.py --on-device`: issue a second certificate with
   `keyAgreement`.
5. `tools/deskid_token.swift`: publish the second key with key exchange allowed
   and implement the key-exchange session call.
6. `tools/hw_smoke_test.py --ecdh`: derive on the board and with `openssl`,
   compare.

Done when: `sc_auth identities` lists both identities; after a cold boot the
card unlocks the disk and no keychain prompt appears. Bench: whether
loginwindow accepts a key-management key from a third-party token driver, or
only from Apple's own PIV driver. If only Apple's, serve the standard PIV AID in
production and accept its PIN field.

## Gap B. Fewer PIN fields

- Apps: the DeskID token driver declares no PIN, so apps show no field.
- Lock Screen and login window: Apple's field stays. Touch first removes the
  wait around it.
- `sudo`: a small PAM module, `pam_deskid`, in `/etc/pam.d/sudo_local`
  (`sufficient`, so the password still works). It speaks PC/SC directly, which
  needs no entitlement, sends a random challenge to `GENERAL AUTHENTICATE` and
  verifies the signature against a public key pinned in a root-owned file. The
  user touches the ring and types nothing. About 250 lines of C.
- System dialogs without the PIN field: an authorization plug-in can do
  this, and products ship that way. It is the one path this document advises
  against building on. An answer on Apple's developer forum says the newer
  lock-screen path is "not compatible with third-party authorisation plug-ins"
  ([thread](https://developer.apple.com/forums/thread/110667)), and plug-in
  authors report problems on macOS 26 and 27
  ([forum tag](https://developer.apple.com/forums/tags/securityinterface)). A wrong entry in the
  authorization database locks an administrator out of their own Mac. Spike it
  on a spare machine; do not ship it yet.

## Gap C. Trust

Touch ID is trusted because the sensor, the matcher and the key sit behind one
hardware boundary. DeskID has three separate parts and one plaintext wire.
The research report of 12 November 2026 sets out three designs; in order:

1. No new hardware, 2 to 3 weeks. Wrap the key with a read-protected HMAC
   eFuse key, HMAC-based NVS encryption, eFuse epoch against counter rollback,
   potting with a tamper loop. Stops an offline copy of the key from a flash
   dump. Does not stop a forged match on the UART.
2. One added chip, 6 to 8 weeks. A secure element holds the P-256 key and
   the attempt counters. The key can no longer be cloned without a laboratory.
3. Two domains, 4 to 6 months. A sensor with an authenticated link, a
   TrustZone microcontroller as the trusted side, the key in the secure
   element, USB handled by code that holds no secrets.

## Host binding with the Mac's Secure Enclave

The Mac's Secure Enclave will hold a P-256 key for any app
(`SecureEnclave.P256` in CryptoKit). The DeskID driver can create one at
pairing and the board can pin its public half. Each request then carries a
proof made inside the enclave, and the board ignores requests without one.

Other processes on the Mac can then no longer spend a
held touch, because they cannot use the driver's enclave key. It also means a
stolen board answers no other computer. Two to three weeks, after Gap A.

## Public claims

- Allowed: "Unlocks your Mac and approves system dialogs and `sudo` with a
  fingerprint, using the smart-card support built into macOS."
- Off limits: "Touch ID", "Secure Enclave", "works with Apple Pay". "Your key
  cannot be extracted" depends on the hardware in Gap C.

## Order of work

1. Merge the hardening fixes and run the bench checklist in the pull request.
2. Gap A, slot 9D.
3. `pam_deskid`.
4. Host binding.
5. Gap C, design 1, then decide on hardware.
