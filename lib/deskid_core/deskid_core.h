// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

#pragma once

#include <cstddef>
#include <cstdint>

namespace deskid {

struct Bytes {
    const uint8_t *data;
    size_t size;
};

class PivCredential {
public:
    virtual ~PivCredential() = default;

    virtual Bytes certificateDer() const = 0;
    virtual Bytes deviceIdentifier() const = 0;
    virtual bool signP256Sha256(Bytes digest, uint8_t *signature, size_t capacity,
                               size_t &signatureLength) = 0;
    virtual bool generateKeyP256(uint8_t *publicKey, size_t capacity,
                                 size_t &publicKeyLength) = 0;
    virtual bool storeCertificate(Bytes certificateDer) = 0;
};

/// How long a fresh applet selection makes the board watch its own ring. Long
/// enough to cover walking up to a Mac that has just woken, short enough that
/// a host which selects often cannot turn it into a permanent load.
constexpr uint8_t kArmOnSelectSeconds = 20;

/// How long a VERIFY that was answered by a fingerprint keeps the next
/// signature unlocked. The same window a request waits for a finger and an
/// early touch stays spendable, so there is one number to explain. Without a
/// bound a card left selected holds a signature in reserve for whichever
/// process asks first, hours later.
constexpr uint64_t kVerifiedValidMilliseconds = 30000;

struct DeviceStatus {
    const char *firmwareVersion = "";
    uint8_t buildVariant = 0;
    uint32_t uptimeSeconds = 0;
    uint8_t resetReason = 0;
    uint32_t freeHeapBytes = 0;
    uint8_t sensorState = 0;
    uint8_t lastSensorConfirmation = 0;
    bool credentialPresent = false;
    uint8_t consecutiveFailures = 0;
    uint32_t lockoutSecondsRemaining = 0;
    uint32_t enrolledTemplates = 0;
    // Whether the sensor has actually reported that count. An empty library
    // opens enrollment to anyone, so "zero" has to be an answer and never the
    // value the counter started at: a sensor that failed to answer at boot
    // must not read as a sensor with nothing enrolled. Not part of the status
    // object.
    bool templateCountKnown = false;
    bool wakeLineHigh = false;
    // Finger first seen to match confirmed, for the most recent successful
    // authentication. Zero until one has happened since boot.
    uint32_t lastMatchMilliseconds = 0;
    uint8_t lastGateOutcome = 0;      // 0x0E
    uint8_t lastGateInstruction = 0;  // 0x0F
    uint32_t secureRequests = 0;      // 0x10: PC_to_RDR_Secure messages seen
    // 0x11: gates answered by a touch that had already happened, and 0x12:
    // how much longer such a touch stays spendable. Together they are how a
    // login that needed no waiting is told apart from one that did.
    uint32_t earlyTouchGates = 0;
    uint8_t touchValidSecondsRemaining = 0;
    // 0x13: GPIO4 under each internal bias, `pullUp << 1 | pullDown`. 0b10 is
    // a pin nothing drives; 0b11 and 0b00 are driven high and low.
    uint8_t wakeLineBias = 0;
    // 0x14: seconds the host has asked the board to keep watching its own
    // sensor. Zero when the ring is watched by the wake line, or not at all.
    uint8_t ringArmedSecondsRemaining = 0;
    // 0x15: the signing routine reproduced its known answer at power-up. A
    // board that reports zero here refuses to sign.
    bool signingSelfTestPassed = false;
};

/// Bytes hedgedNonceSeed() writes.
constexpr size_t kHedgedNonceSeedSize = 191;

/// Seed for the HMAC_DRBG that picks an ECDSA P-256 nonce:
///
///     Z || 63 zero bytes || x || 32 zero bytes || bits2octets(h)
///
/// Z is fresh randomness, x the private scalar and h the SHA-256 digest being
/// signed. This is RFC 6979 with the input of
/// draft-irtf-cfrg-det-sigs-with-noise-05 section 4. A nonce drawn from it
/// stays secret and unique per digest when the random generator fails, which
/// plain randomized ECDSA does not survive, and it differs between two
/// signatures of one digest, which is what the fault attacks on plain RFC 6979
/// need it not to do. The zeros make V || 0x00 || Z and x each fill whole
/// SHA-256 blocks, so the scalar is hashed from a state Z has already
/// randomized.
void hedgedNonceSeed(const uint8_t randomness[32], const uint8_t scalar[32],
                     const uint8_t digest[32],
                     uint8_t seed[kHedgedNonceSeedSize]);

class DeviceDiagnostics {
public:
    virtual ~DeviceDiagnostics() = default;

    virtual DeviceStatus status() const = 0;
    /// Monotonic time since boot. The applet has no clock of its own and
    /// needs one to let a verified touch expire.
    virtual uint64_t uptimeMilliseconds() const = 0;
    virtual bool enterDownloadMode() = 0;
    virtual bool enrollStep(uint8_t &stage) = 0;
    virtual bool forgetFingerprints() = 0;
    /// Watch the sensor for `seconds`, so a touch given before the host asks
    /// still counts. Costs an image capture per poll, which is why it is
    /// bounded and host-driven rather than always on.
    virtual bool armRing(uint8_t seconds) = 0;
};

enum class TransceiveStatus {
    complete,
    userPresenceRequired,
};

class PivApplet {
public:
    static constexpr size_t kMaximumResponseData = 2048;

    PivApplet(PivCredential &credential, DeviceDiagnostics &diagnostics);

    TransceiveStatus transceive(const uint8_t *command, size_t commandLength,
                                bool userPresent, uint8_t *response,
                                size_t responseCapacity, size_t &responseLength);
    void reset();

private:
    void drainPending(size_t requestedLength, uint8_t *response,
                      size_t responseCapacity, size_t &responseLength);
    bool provisioned() const;
    bool verificationHeld();

    PivCredential &credential_;
    DeviceDiagnostics &diagnostics_;
    uint8_t pendingResponse_[kMaximumResponseData]{};
    size_t pendingOffset_ = 0;
    size_t pendingLength_ = 0;
    bool selected_ = false;
    bool verified_ = false;
    uint64_t verifiedAtMilliseconds_ = 0;
};

class RateLimiter {
public:
    RateLimiter(uint32_t failureThreshold, uint64_t baseLockoutMilliseconds,
                uint64_t maximumLockoutMilliseconds);

    bool locked(uint64_t nowMilliseconds) const;
    uint64_t lockoutMillisecondsRemaining(uint64_t nowMilliseconds) const;
    uint32_t consecutiveFailures() const;
    uint32_t lockoutCount() const;
    void restore(uint32_t consecutiveFailures, uint32_t lockoutCount,
                 uint64_t nowMilliseconds);
    void recordFailure(uint64_t nowMilliseconds);
    void recordSuccess();

private:
    uint64_t lockoutDuration(uint32_t lockoutCount) const;

    uint32_t failureThreshold_;
    uint64_t baseLockoutMilliseconds_;
    uint64_t maximumLockoutMilliseconds_;
    uint32_t consecutiveFailures_ = 0;
    uint32_t lockoutCount_ = 0;
    uint64_t lockedUntilMilliseconds_ = 0;
};

/// Where the limiter's counters outlive a power cycle.
class LimiterStore {
public:
    virtual ~LimiterStore() = default;

    virtual bool save(uint32_t consecutiveFailures, uint32_t lockoutCount) = 0;
};

// Charges a match attempt before the sensor is asked for its verdict.
//
// The verdict is the secret. Counting a failure after hearing it leaves a gap
// between the answer and the write, and pulling the plug inside it erases the
// attempt. Five tries then become as many as the attacker has patience for. Smart cards close that gap by spending the try
// first and refunding it on success, and so does this: charge() counts the
// attempt as failed and writes that down, and only then may the sensor be
// asked. matched() is the refund.
//
// An attempt that cannot be written down is refused. A limiter that only
// exists in memory is the bug this class is here to remove.
class AttemptLedger {
public:
    AttemptLedger(RateLimiter &limiter, LimiterStore &store);

    /// Call immediately before asking the sensor for a verdict. False means
    /// the sensor must not be asked: locked out, or the charge did not reach
    /// storage.
    bool charge(uint64_t nowMilliseconds);
    /// The verdict was a match. Clears the counters and persists that.
    void matched();

private:
    RateLimiter &limiter_;
    LimiterStore &store_;
};

// A fingerprint match that happened before any host asked for one.
//
// Touch ID is live before the prompt appears; the prompt is what happens
// afterwards. DeskID needs the same shape because macOS draws its own PIN
// field for every smart card and no public setting removes it: without a
// window like this the sensor stays dark until those meaningless digits have
// been typed, and the user waits twice. With it the touch can happen on
// arrival and the login instruction is answered with no wait at all.
//
// The window is the whole security trade — long enough to cover walking from
// the sensor to the keyboard, short enough that a touch left behind is not a
// standing invitation — so it is single use and only the two login
// instructions can spend it.
class EarlyTouch {
public:
    explicit EarlyTouch(uint64_t validMilliseconds);

    void record(uint64_t nowMilliseconds);
    bool held(uint64_t nowMilliseconds) const;
    uint64_t millisecondsRemaining(uint64_t nowMilliseconds) const;
    /// Spends the window if this instruction is allowed to and one is held.
    /// Spending clears it whether or not what follows succeeds, so one touch
    /// is one operation and can never be replayed.
    bool spend(uint8_t instruction, uint64_t nowMilliseconds);
    void clear();
    uint32_t gates() const;

    /// Signing in is the only thing an already-given touch may do. Enrolling a
    /// finger, writing a key or certificate, emptying the sensor and rebooting
    /// into download mode all still demand a live match while the host waits,
    /// because those are the operations an attacker wants and none of them is
    /// on the path this window exists to shorten.
    static bool maySpend(uint8_t instruction);

private:
    uint64_t validMilliseconds_;
    uint64_t expiresAtMilliseconds_ = 0;
    uint32_t gates_ = 0;
};

/// The longest a host may ask the board to type for it. Long enough to reach
/// the ring after a prompt appears, short enough that an arming nobody used
/// has lapsed before another window takes the keyboard.
constexpr uint8_t kMaximumAutotypeSeconds = 15;

// The digits macOS asks for, typed by the board.
//
// macOS draws a PIN field for every smart card and the applet ignores what is
// typed into it: the fingerprint is the check. So after a match the board can
// type the digits and Return itself over USB HID, and a login is one touch.
// What it types is a constant and unlocks nothing. The signature that follows
// still has to spend the fingerprint match, as it does when a person types.
//
// The board cannot see the screen. The host says when a PIN field has the
// keyboard, and that permission is short and single use, because keystrokes
// sent at any other moment land in whatever window is in front.
class Autotype {
public:
    /// Reports in one emission: a press and a release for each key.
    static constexpr size_t kReportCount = 14;

    /// Zero seconds disarms.
    void arm(uint8_t seconds, uint64_t nowMilliseconds);
    uint8_t secondsRemaining(uint64_t nowMilliseconds) const;
    /// True once per arming, inside its window. The caller then types.
    bool take(uint64_t nowMilliseconds);
    uint32_t emissions() const;

    /// The `index`-th eight-byte keyboard report of an emission.
    static void report(size_t index, uint8_t report[8]);

private:
    uint64_t armedUntilMilliseconds_ = 0;
    uint32_t emissions_ = 0;
};

}  // namespace deskid