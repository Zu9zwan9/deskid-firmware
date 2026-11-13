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
};

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

// The R503's touch-sense output, as far as it can be believed.
//
// The sensor holds WAKEUP at one level while the ring is empty and drives it
// to the other for as long as a finger rests there. Which level means a
// finger is a property of the sensor and is passed in. The first firmware to
// use the line had it backwards and read an empty ring as a finger.
//
// A level that has never changed proves nothing. A wire that was never
// soldered and one bridged to a rail both read as a steady, confident answer,
// so the line counts only after it has been seen at both levels.
class WakeLine {
public:
    explicit WakeLine(bool touchedLevel);

    void observe(bool level);
    bool usable() const;
    /// A finger is on the ring. Always false until the line is usable.
    bool touched(bool level) const;

private:
    bool touchedLevel_;
    uint8_t seen_ = 0;
};

}  // namespace deskid