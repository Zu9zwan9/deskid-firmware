#include "sensor_link.h"

namespace deskid::fpc {
namespace {

// ponytail: identify and status fit in 64 bytes; raise it when a secure
// command with a bigger payload has to pass the gate.
constexpr size_t kMaximumPlaintext = 64;

uint16_t read16(const uint8_t *bytes) {
    return static_cast<uint16_t>(bytes[0] | (bytes[1] << 8));
}

Verdict reject(Reason reason) { return {Outcome::Rejected, reason, 0}; }

constexpr Verdict kDiagnostic{Outcome::Diagnostic, Reason::None, 0};

bool diagnosticCommand(uint16_t command) {
    return command == kCmdStatus || command == kCmdVersion ||
           command == kCmdGetSystemConfig;
}

}  // namespace

SensorLinkGate::SensorLinkGate(LinkState &link, Aead &aead, TagSource &tags,
                               TemplateAllowList &allowList, IvJournal &journal)
    : link_(link), aead_(aead), tags_(tags), allowList_(allowList),
      journal_(journal) {}

uint16_t SensorLinkGate::beginIdentify() {
    pendingTag_ = tags_.next();
    pending_ = true;
    return pendingTag_;
}

Verdict SensorLinkGate::onFrame(const uint8_t *frame, size_t length) {
    if (frame == nullptr || length < kHeaderSize ||
        length - kHeaderSize != read16(frame + 6) ||
        read16(frame) != kProtocolVersion) {
        return reject(Reason::Malformed);
    }
    const uint16_t type = read16(frame + 2);
    const uint16_t flags = read16(frame + 4);
    if (type != kTypeResponse && type != kTypeEvent) {
        return reject(Reason::Malformed);
    }
    if (flags & kFlagSenderHost) {
        return reject(Reason::Reflected);
    }
    if (!(flags & kFlagSenderApp)) {
        return reject(Reason::Malformed);
    }
    const uint8_t *payload = frame + kHeaderSize;
    const size_t payloadLength = length - kHeaderSize;

    if (!(flags & kFlagSecure)) {
        if (payloadLength < 4) {
            return reject(Reason::Malformed);
        }
        const uint16_t command = read16(payload);
        if (link_.keyed()) {
            // Once keyed, only status-type replies may travel in the clear.
            return diagnosticCommand(command) ? kDiagnostic
                                              : reject(Reason::Plaintext);
        }
        return command == kCmdIdentify ? identify(payload, payloadLength, nullptr)
                                       : kDiagnostic;
    }

    if (payloadLength < kIvSize + kGcmTagSize + 4 ||
        payloadLength - kIvSize - kGcmTagSize > kMaximumPlaintext) {
        return reject(Reason::Malformed);
    }
    const uint8_t *iv = payload;
    if (journal_.seen(iv)) {
        return reject(Reason::Replayed);
    }
    const size_t plaintextLength = payloadLength - kIvSize - kGcmTagSize;
    uint8_t plaintext[kMaximumPlaintext];
    if (!aead_.open(frame, kHeaderSize, iv, payload + kIvSize,
                    payload + kIvSize + kGcmTagSize, plaintextLength,
                    plaintext)) {
        return reject(Reason::Forged);
    }
    return read16(plaintext) == kCmdIdentify
               ? identify(plaintext, plaintextLength, iv)
               : kDiagnostic;
}

Verdict SensorLinkGate::identify(const uint8_t *payload, size_t length,
                                 const uint8_t *iv) {
    if (length != kIdentifyResponseSize) {
        return reject(Reason::Malformed);
    }
    const uint16_t match = read16(payload + 4);
    if (match != kIdentifyMatch && match != kIdentifyNoMatch) {
        return reject(Reason::Malformed);
    }
    if (!pending_) {
        return reject(Reason::Unsolicited);
    }
    // Any answer spends the request, so a guessed tag on an unkeyed bench
    // link gets one try per request, not 65,536.
    pending_ = false;
    if (read16(payload + 10) != pendingTag_) {
        return reject(Reason::ForeignTag);
    }
    if (iv != nullptr && !journal_.record(iv)) {
        return reject(Reason::JournalFull);
    }
    if (match == kIdentifyNoMatch) {
        return {Outcome::NoMatch, Reason::None, 0};
    }
    const uint16_t templateId = read16(payload + 8);
    if (read16(payload + 6) != kIdTypeSpecified || !allowList_.allowed(templateId)) {
        return reject(Reason::UnknownTemplate);
    }
    return {Outcome::Match, Reason::None, templateId};
}

}  // namespace deskid::fpc
