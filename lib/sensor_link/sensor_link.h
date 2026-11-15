#pragma once

#include <cstddef>
#include <cstdint>

// The FPC2534 says "match" in a two-byte field. Anything on the SPI wires can
// say it too, so a verdict counts only when the frame proves where it came
// from and which request it answers.
namespace deskid::fpc {

constexpr uint16_t kProtocolVersion = 0x0004;
constexpr uint16_t kTypeResponse = 0x12;
constexpr uint16_t kTypeEvent = 0x13;
constexpr uint16_t kFlagSecure = 0x0001;
constexpr uint16_t kFlagSenderHost = 0x0010;
constexpr uint16_t kFlagSenderApp = 0x0040;
constexpr uint16_t kCmdStatus = 0x0040;
constexpr uint16_t kCmdVersion = 0x0041;
constexpr uint16_t kCmdIdentify = 0x0055;
constexpr uint16_t kCmdGetSystemConfig = 0x006A;
constexpr uint16_t kIdentifyMatch = 0x61EC;
constexpr uint16_t kIdentifyNoMatch = 0xBAAD;
constexpr uint16_t kIdTypeSpecified = 0x3034;
constexpr size_t kHeaderSize = 8;
constexpr size_t kIvSize = 12;
constexpr size_t kGcmTagSize = 16;
constexpr size_t kIdentifyResponseSize = 12;

/// Whether the sensor has been given the link key.
struct LinkState {
    virtual ~LinkState() = default;
    virtual bool keyed() const = 0;
};

/// AES-GCM open with the link key. False means the tag did not verify.
struct Aead {
    virtual ~Aead() = default;
    virtual bool open(const uint8_t *aad, size_t aadLength, const uint8_t *iv,
                      const uint8_t *gcmTag, const uint8_t *ciphertext,
                      size_t length, uint8_t *plaintext) = 0;
};

/// Fresh, unpredictable request tags from a seeded DRBG or the secure element.
struct TagSource {
    virtual ~TagSource() = default;
    virtual uint16_t next() = 0;
};

/// Template ids enrolled through DeskID, held outside the sensor.
struct TemplateAllowList {
    virtual ~TemplateAllowList() = default;
    virtual bool allowed(uint16_t templateId) const = 0;
};

/// IVs already accepted, kept across power cycles.
struct IvJournal {
    virtual ~IvJournal() = default;
    virtual bool seen(const uint8_t *iv) const = 0;
    virtual bool record(const uint8_t *iv) = 0;
};

enum class Outcome { Match, NoMatch, Diagnostic, Rejected };

enum class Reason {
    None,
    Malformed,
    Plaintext,
    Reflected,
    Replayed,
    Forged,
    Unsolicited,
    ForeignTag,
    UnknownTemplate,
    JournalFull,
};

struct Verdict {
    Outcome outcome;
    Reason reason;
    uint16_t templateId;
};

class SensorLinkGate {
public:
    SensorLinkGate(LinkState &link, Aead &aead, TagSource &tags,
                   TemplateAllowList &allowList, IvJournal &journal);

    /// Returns the tag to put in the next CMD_IDENTIFY request. Only the
    /// response carrying it can be a verdict, and only once.
    uint16_t beginIdentify();

    /// Judges one frame read from the sensor. Anything but Match is not a
    /// match; the caller never refunds the attempt it charged.
    Verdict onFrame(const uint8_t *frame, size_t length);

private:
    Verdict identify(const uint8_t *payload, size_t length, const uint8_t *iv);

    LinkState &link_;
    Aead &aead_;
    TagSource &tags_;
    TemplateAllowList &allowList_;
    IvJournal &journal_;
    bool pending_ = false;
    uint16_t pendingTag_ = 0;
};

}  // namespace deskid::fpc
