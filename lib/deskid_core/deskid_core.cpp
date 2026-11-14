// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

#include "deskid_core.h"

#include <algorithm>
#include <cstring>

namespace deskid {
namespace {

// DeskID's own application identifier, F0 "DeskID". A private AID keeps
// Apple's built-in PIV driver — which hard-codes a PIN for slot 9A — from
// claiming the card, so the DeskID token extension is the only driver that
// ever sees it. The standard PIV AID is served too when DESKID_ALLOW_PIV_AID
// is set: bring-up boards and hosts that have no DeskID driver yet.
constexpr uint8_t kDeskIdAid[] = {0xF0, 0x44, 0x65, 0x73, 0x6B, 0x49, 0x44};
constexpr uint8_t kPivAid[] = {0xA0, 0x00, 0x00, 0x03, 0x08,
                               0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
constexpr uint8_t kSelectResponse[] = {
    0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08,
};

// Responses can carry a shared secret, so buffers that held one are cleared
// in a way the optimiser cannot remove.
void wipe(void *data, size_t length) {
    volatile uint8_t *cursor = static_cast<volatile uint8_t *>(data);
    while (length-- != 0) {
        *cursor++ = 0;
    }
}

struct Apdu {
    uint8_t cla = 0;
    uint8_t instruction = 0;
    uint8_t parameter1 = 0;
    uint8_t parameter2 = 0;
    Bytes data{nullptr, 0};
    size_t expectedLength = 256;
};

class Writer {
public:
    Writer(uint8_t *data, size_t capacity) : data_(data), capacity_(capacity) {}

    bool byte(uint8_t value) {
        if (size_ == capacity_) {
            return false;
        }
        data_[size_++] = value;
        return true;
    }

    bool bytes(const uint8_t *value, size_t length) {
        if (length > capacity_ - size_) {
            return false;
        }
        std::memcpy(data_ + size_, value, length);
        size_ += length;
        return true;
    }

    bool length(size_t value) {
        if (value < 0x80) {
            return byte(static_cast<uint8_t>(value));
        }
        if (value <= 0xFF) {
            return byte(0x81) && byte(static_cast<uint8_t>(value));
        }
        return value <= 0xFFFF && byte(0x82) &&
               byte(static_cast<uint8_t>(value >> 8)) &&
               byte(static_cast<uint8_t>(value));
    }

    size_t size() const { return size_; }

private:
    uint8_t *data_;
    size_t capacity_;
    size_t size_ = 0;
};

bool decodeLength(Bytes encoded, size_t &offset, size_t &length) {
    if (offset >= encoded.size) {
        return false;
    }

    const uint8_t first = encoded.data[offset++];
    if ((first & 0x80) == 0) {
        length = first;
        return true;
    }

    const size_t byteCount = first & 0x7F;
    if (byteCount == 0 || byteCount > 2 || byteCount > encoded.size - offset) {
        return false;
    }

    length = 0;
    for (size_t index = 0; index < byteCount; ++index) {
        length = (length << 8) | encoded.data[offset++];
    }
    return length <= encoded.size - offset;
}

size_t encodedLengthSize(size_t length) {
    return length < 0x80 ? 1 : (length <= 0xFF ? 2 : 3);
}

bool writeStatusByte(Writer &writer, uint8_t tag, uint8_t value) {
    return writer.byte(tag) && writer.byte(1) && writer.byte(value);
}

bool writeStatusBigEndian32(Writer &writer, uint8_t tag, uint32_t value) {
    return writer.byte(tag) && writer.byte(4) &&
           writer.byte(static_cast<uint8_t>(value >> 24)) &&
           writer.byte(static_cast<uint8_t>(value >> 16)) &&
           writer.byte(static_cast<uint8_t>(value >> 8)) &&
           writer.byte(static_cast<uint8_t>(value));
}

bool parseApdu(const uint8_t *command, size_t commandLength, Apdu &apdu) {
    if (command == nullptr || commandLength < 4) {
        return false;
    }

    apdu.cla = command[0];
    apdu.instruction = command[1];
    apdu.parameter1 = command[2];
    apdu.parameter2 = command[3];
    if (commandLength == 4) {
        return true;
    }

    if (commandLength == 5) {
        apdu.expectedLength = command[4] == 0 ? 256 : command[4];
        return true;
    }

    if (command[4] != 0) {
        const size_t dataLength = command[4];
        if (dataLength > commandLength - 5 ||
            (commandLength != 5 + dataLength && commandLength != 6 + dataLength)) {
            return false;
        }
        apdu.data = {command + 5, dataLength};
        if (commandLength == 6 + dataLength) {
            apdu.expectedLength = command[5 + dataLength] == 0
                                      ? 256
                                      : command[5 + dataLength];
        }
        return true;
    }

    if (commandLength < 7) {
        return false;
    }
    const size_t extendedLength =
        (static_cast<size_t>(command[5]) << 8) | command[6];
    if (commandLength == 7) {
        apdu.expectedLength = extendedLength == 0 ? 65536 : extendedLength;
        return true;
    }
    if (extendedLength == 0 || extendedLength > commandLength - 7 ||
        (commandLength != 7 + extendedLength &&
         commandLength != 9 + extendedLength)) {
        return false;
    }
    apdu.data = {command + 7, extendedLength};
    if (commandLength == 9 + extendedLength) {
        const size_t expected =
            (static_cast<size_t>(command[7 + extendedLength]) << 8) |
            command[8 + extendedLength];
        apdu.expectedLength = expected == 0 ? 65536 : expected;
    }
    return true;
}

void status(uint16_t value, uint8_t *response, size_t capacity,
            size_t &responseLength) {
    responseLength = 0;
    if (response == nullptr || capacity < 2) {
        return;
    }
    response[0] = static_cast<uint8_t>(value >> 8);
    response[1] = static_cast<uint8_t>(value);
    responseLength = 2;
}

bool matchesAid(Bytes candidate) {
    if (candidate.size == sizeof(kDeskIdAid) &&
        std::memcmp(candidate.data, kDeskIdAid, candidate.size) == 0) {
        return true;
    }
#if defined(DESKID_ALLOW_PIV_AID)
    return candidate.size >= 5 && candidate.size <= sizeof(kPivAid) &&
           std::memcmp(candidate.data, kPivAid, candidate.size) == 0;
#else
    return false;
#endif
}

bool requestedTag(Bytes data, const uint8_t *tag, size_t tagLength) {
    if (data.size < 2 || data.data[0] != 0x5C) {
        return false;
    }
    size_t offset = 1;
    size_t length = 0;
    return decodeLength(data, offset, length) && length == tagLength &&
           offset + length == data.size &&
           std::memcmp(data.data + offset, tag, tagLength) == 0;
}

bool parseKeyGenerationTemplate(Bytes data) {
    if (data.size < 2 || data.data[0] != 0xAC) {
        return false;
    }
    size_t offset = 1;
    size_t outerLength = 0;
    if (!decodeLength(data, offset, outerLength) ||
        offset + outerLength != data.size) {
        return false;
    }

    const size_t end = offset + outerLength;
    bool p256Requested = false;
    while (offset < end) {
        const uint8_t tag = data.data[offset++];
        size_t length = 0;
        if (!decodeLength(data, offset, length) || length > end - offset) {
            return false;
        }
        if (tag == 0x80) {
            if (length != 1 || data.data[offset] != 0x11) {
                return false;
            }
            p256Requested = true;
        }
        offset += length;
    }
    return p256Requested;
}

bool parsePutDataObject(Bytes data, Bytes &tagList, Bytes &object) {
    if (data.size < 2 || data.data[0] != 0x5C) {
        return false;
    }
    size_t offset = 1;
    size_t tagLength = 0;
    if (!decodeLength(data, offset, tagLength)) {
        return false;
    }
    tagList = {data.data + offset, tagLength};
    offset += tagLength;

    if (offset >= data.size || data.data[offset++] != 0x53) {
        return false;
    }
    size_t objectLength = 0;
    if (!decodeLength(data, offset, objectLength) ||
        offset + objectLength != data.size) {
        return false;
    }
    object = {data.data + offset, objectLength};
    return true;
}

bool parseCertificateContent(Bytes object, Bytes &certificate) {
    if (object.size < 2 || object.data[0] != 0x70) {
        return false;
    }
    size_t offset = 1;
    size_t length = 0;
    if (!decodeLength(object, offset, length) || length == 0) {
        return false;
    }
    certificate = {object.data + offset, length};
    return true;
}

bool parseAuthenticationTemplate(Bytes data, Bytes &digest) {
    if (data.size < 2 || data.data[0] != 0x7C) {
        return false;
    }
    size_t offset = 1;
    size_t outerLength = 0;
    if (!decodeLength(data, offset, outerLength) || offset + outerLength != data.size) {
        return false;
    }

    const size_t end = offset + outerLength;
    bool responseRequestSeen = false;
    bool digestSeen = false;
    while (offset < end) {
        const uint8_t tag = data.data[offset++];
        size_t length = 0;
        if (!decodeLength(data, offset, length) || length > end - offset) {
            return false;
        }
        if (tag == 0x82 && length == 0) {
            responseRequestSeen = true;
        } else if (tag == 0x81 && !digestSeen) {
            digest = {data.data + offset, length};
            digestSeen = true;
        } else {
            return false;
        }
        offset += length;
    }
    return responseRequestSeen && digestSeen && digest.size == 32;
}

// GENERAL AUTHENTICATE for the key management key: 7C { 82 00, 85 <point> },
// where the point is the other party's uncompressed P-256 public key.
bool parseKeyAgreementTemplate(Bytes data, Bytes &peerPoint) {
    if (data.size < 2 || data.data[0] != 0x7C) {
        return false;
    }
    size_t offset = 1;
    size_t outerLength = 0;
    if (!decodeLength(data, offset, outerLength) ||
        offset + outerLength != data.size) {
        return false;
    }

    const size_t end = offset + outerLength;
    bool responseRequestSeen = false;
    bool pointSeen = false;
    while (offset < end) {
        const uint8_t tag = data.data[offset++];
        size_t length = 0;
        if (!decodeLength(data, offset, length) || length > end - offset) {
            return false;
        }
        if (tag == 0x82 && length == 0) {
            responseRequestSeen = true;
        } else if (tag == 0x85 && !pointSeen) {
            peerPoint = {data.data + offset, length};
            pointSeen = true;
        } else {
            return false;
        }
        offset += length;
    }
    return responseRequestSeen && pointSeen && peerPoint.size == 65;
}

}  // namespace

PivApplet::PivApplet(PivCredential &credential, DeviceDiagnostics &diagnostics)
    : credential_(credential), diagnostics_(diagnostics) {}

void PivApplet::clearPending() {
    wipe(pendingResponse_, pendingLength_);
    pendingOffset_ = 0;
    pendingLength_ = 0;
}

void PivApplet::reset() {
    clearPending();
    selected_ = false;
    verified_ = false;
    verifiedAtMilliseconds_ = 0;
}

void PivApplet::drainPending(size_t requestedLength, uint8_t *response,
                             size_t responseCapacity,
                             size_t &responseLength) {
    const size_t remaining = pendingLength_ - pendingOffset_;
    const size_t chunkLength =
        std::min({remaining, requestedLength, responseCapacity - 2});
    std::memcpy(response, pendingResponse_ + pendingOffset_, chunkLength);
    pendingOffset_ += chunkLength;
    const size_t afterChunk = pendingLength_ - pendingOffset_;
    if (afterChunk == 0) {
        clearPending();
        response[chunkLength] = 0x90;
        response[chunkLength + 1] = 0x00;
    } else {
        response[chunkLength] = 0x61;
        response[chunkLength + 1] =
            static_cast<uint8_t>(std::min<size_t>(afterChunk, 0xFF));
    }
    responseLength = chunkLength + 2;
}

TransceiveStatus PivApplet::transceive(const uint8_t *command,
                                       size_t commandLength, bool userPresent,
                                       uint8_t *response,
                                       size_t responseCapacity,
                                       size_t &responseLength) {
    responseLength = 0;
    if (response == nullptr || responseCapacity < 2) {
        return TransceiveStatus::complete;
    }
    Apdu apdu;
    if (!parseApdu(command, commandLength, apdu)) {
        status(0x6700, response, responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    auto libraryKnownEmpty = [&]() {
        const DeviceStatus device = diagnostics_.status();
        return device.templateCountKnown && device.enrolledTemplates == 0;
    };

    auto sendData = [&](const uint8_t *data, size_t length,
                        size_t requestedLength) {
        pendingLength_ = std::min(length, sizeof(pendingResponse_));
        std::memcpy(pendingResponse_, data, pendingLength_);
        pendingOffset_ = 0;
        drainPending(requestedLength, response, responseCapacity,
                     responseLength);
    };

    if (apdu.instruction == 0xC0) {
        if (apdu.cla != 0x00 || apdu.parameter1 != 0x00 ||
            apdu.parameter2 != 0x00 || pendingLength_ == 0) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        drainPending(apdu.expectedLength, response, responseCapacity,
                     responseLength);
        return TransceiveStatus::complete;
    }

    clearPending();

    if (apdu.instruction == 0xA4) {
        if ((apdu.cla & 0xEF) != 0x00 || apdu.parameter1 != 0x04 ||
            !matchesAid(apdu.data)) {
            status(0x6A82, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        // Selecting the applet is the host saying it is interested in this
        // card right now, and at the lock screen that happens when the screen
        // wakes — which is when the user is walking up to it. So a board
        // with no usable wake line may poll its ring, briefly. Whether a
        // touch then counts is not decided here: see idleRingListens.
        //
        // Briefly is the whole safety argument. Watching costs an image
        // capture per poll on a board whose wake line cannot be trusted, and
        // doing that continuously browned the 3V3 rail out badly enough to
        // power-cycle the device. A window
        // per selection is bounded by how often a host selects.
        if (!selected_) {
            diagnostics_.armRing(kArmOnSelectSeconds);
        }
        selected_ = true;
        verified_ = false;
        sendData(kSelectResponse, sizeof(kSelectResponse), apdu.expectedLength);
        return TransceiveStatus::complete;
    }

    if (!selected_) {
        status(0x6985, response, responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0xCB) {
        if (apdu.cla != 0x00 || apdu.parameter1 != 0x3F ||
            apdu.parameter2 != 0xFF) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }

        constexpr uint8_t discoveryTag[] = {0x7E};
        constexpr uint8_t chuidTag[] = {0x5F, 0xC1, 0x02};
        constexpr uint8_t certificateTag[] = {0x5F, 0xC1, 0x05};
        constexpr uint8_t keyManagementTag[] = {0x5F, 0xC1, 0x0B};
        constexpr uint8_t cccTag[] = {0x5F, 0xC1, 0x07};
        constexpr uint8_t statusTag[] = {0x5F, 0xFF, 0x01};
        if (requestedTag(apdu.data, discoveryTag, sizeof(discoveryTag))) {
            constexpr uint8_t discovery[] = {
                0x7E, 0x12, 0x4F, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00,
                0x00, 0x10, 0x00, 0x01, 0x00, 0x5F, 0x2F, 0x02, 0x40, 0x00,
            };
            sendData(discovery, sizeof(discovery), apdu.expectedLength);
            return TransceiveStatus::complete;
        }

        const Bytes identifier = credential_.deviceIdentifier();
        if (requestedTag(apdu.data, chuidTag, sizeof(chuidTag))) {
            if (identifier.data == nullptr || identifier.size != 16) {
                status(0x6A82, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            constexpr uint8_t fascNumber[] = {
                0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39, 0xCE,
                0x73, 0x9D, 0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10,
                0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB,
            };
            uint8_t guid[16];
            std::memcpy(guid, identifier.data, sizeof(guid));
            guid[6] = static_cast<uint8_t>((guid[6] & 0x0F) | 0x40);
            guid[8] = static_cast<uint8_t>((guid[8] & 0x3F) | 0x80);

            uint8_t chuid[61];
            Writer writer(chuid, sizeof(chuid));
            constexpr uint8_t expiration[] = {'2', '0', '3', '0',
                                               '0', '1', '0', '1'};
            if (!writer.byte(0x53) || !writer.byte(0x3B) ||
                !writer.byte(0x30) || !writer.byte(sizeof(fascNumber)) ||
                !writer.bytes(fascNumber, sizeof(fascNumber)) ||
                !writer.byte(0x34) || !writer.byte(sizeof(guid)) ||
                !writer.bytes(guid, sizeof(guid)) || !writer.byte(0x35) ||
                !writer.byte(sizeof(expiration)) ||
                !writer.bytes(expiration, sizeof(expiration)) ||
                !writer.bytes(reinterpret_cast<const uint8_t *>(
                                  "\x3E\x00\xFE\x00"),
                              4)) {
                status(0x6F00, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            sendData(chuid, writer.size(), apdu.expectedLength);
            return TransceiveStatus::complete;
        }

        if (requestedTag(apdu.data, cccTag, sizeof(cccTag))) {
            if (identifier.data == nullptr || identifier.size < 14) {
                status(0x6A82, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            uint8_t ccc[55];
            Writer writer(ccc, sizeof(ccc));
            constexpr uint8_t prefix[] = {0x53, 0x33, 0xF0, 0x15, 0xA0,
                                          0x00, 0x00, 0x01, 0x16, 0xFF, 0x02};
            constexpr uint8_t suffix[] = {
                0xF1, 0x01, 0x21, 0xF2, 0x01, 0x21, 0xF3, 0x00,
                0xF4, 0x01, 0x00, 0xF5, 0x01, 0x10, 0xF6, 0x00,
                0xF7, 0x00, 0xFA, 0x00, 0xFB, 0x00, 0xFC, 0x00,
                0xFD, 0x00, 0xFE, 0x00,
            };
            if (!writer.bytes(prefix, sizeof(prefix)) ||
                !writer.bytes(identifier.data, 14) ||
                !writer.bytes(suffix, sizeof(suffix))) {
                status(0x6F00, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            sendData(ccc, writer.size(), apdu.expectedLength);
            return TransceiveStatus::complete;
        }

        const bool keyManagementRequested = requestedTag(
            apdu.data, keyManagementTag, sizeof(keyManagementTag));
        if (keyManagementRequested ||
            requestedTag(apdu.data, certificateTag, sizeof(certificateTag))) {
            const Bytes certificate = credential_.certificateDer(
                keyManagementRequested ? Slot::keyManagement
                                       : Slot::authentication);
            if (certificate.data == nullptr || certificate.size == 0 ||
                certificate.size > kMaximumResponseData - 16) {
                status(0x6A82, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }

            uint8_t encoded[kMaximumResponseData];
            Writer writer(encoded, sizeof(encoded));
            const size_t innerLength =
                1 + encodedLengthSize(certificate.size) + certificate.size + 5;
            if (!writer.byte(0x53) || !writer.length(innerLength) ||
                !writer.byte(0x70) || !writer.length(certificate.size) ||
                !writer.bytes(certificate.data, certificate.size) ||
                !writer.bytes(reinterpret_cast<const uint8_t *>("\x71\x01\x00\xFE\x00"),
                              5)) {
                status(0x6F00, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            sendData(encoded, writer.size(), apdu.expectedLength);
            return TransceiveStatus::complete;
        }

        if (requestedTag(apdu.data, statusTag, sizeof(statusTag))) {
            const DeviceStatus device = diagnostics_.status();
            const char *version = device.firmwareVersion == nullptr
                                      ? ""
                                      : device.firmwareVersion;
            const size_t versionLength =
                std::min<size_t>(std::strlen(version), 16);

            // 53 L, 85 fixed bytes, and up to 16 of version.
            uint8_t encoded[2 + 85 + 16];
            Writer writer(encoded, sizeof(encoded));
            if (!writer.byte(0x53) || !writer.length(85 + versionLength) ||
                !writer.byte(0x01) ||
                !writer.byte(static_cast<uint8_t>(versionLength)) ||
                !writer.bytes(reinterpret_cast<const uint8_t *>(version),
                              versionLength) ||
                !writeStatusByte(writer, 0x02, device.buildVariant) ||
                !writeStatusBigEndian32(writer, 0x03, device.uptimeSeconds) ||
                !writeStatusByte(writer, 0x04, device.resetReason) ||
                !writeStatusBigEndian32(writer, 0x05, device.freeHeapBytes) ||
                !writeStatusByte(writer, 0x06, device.sensorState) ||
                !writeStatusByte(writer, 0x07,
                                 device.lastSensorConfirmation) ||
                !writeStatusByte(writer, 0x08, device.credentialPresent) ||
                !writeStatusByte(writer, 0x09, device.consecutiveFailures) ||
                !writeStatusBigEndian32(writer, 0x0A,
                                        device.lockoutSecondsRemaining) ||
                !writeStatusBigEndian32(writer, 0x0B,
                                        device.enrolledTemplates) ||
                !writeStatusByte(writer, 0x0C, device.wakeLineHigh) ||
                !writeStatusBigEndian32(writer, 0x0D,
                                        device.lastMatchMilliseconds) ||
                !writeStatusByte(writer, 0x0E, device.lastGateOutcome) ||
                !writeStatusByte(writer, 0x0F, device.lastGateInstruction) ||
                !writeStatusBigEndian32(writer, 0x10, device.secureRequests) ||
                !writeStatusBigEndian32(writer, 0x11, device.earlyTouchGates) ||
                !writeStatusByte(writer, 0x12,
                                 device.touchValidSecondsRemaining) ||
                !writeStatusByte(writer, 0x13, device.wakeLineBias) ||
                !writeStatusByte(writer, 0x14,
                                 device.ringArmedSecondsRemaining) ||
                !writeStatusByte(writer, 0x15,
                                 device.signingSelfTestPassed) ||
                !writer.bytes(reinterpret_cast<const uint8_t *>("\xFE\x00"),
                              2)) {
                status(0x6F00, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            sendData(encoded, writer.size(), apdu.expectedLength);
            return TransceiveStatus::complete;
        }

        status(0x6A82, response, responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0x20) {
        if (apdu.cla != 0x00 || apdu.parameter1 != 0x00 ||
            apdu.parameter2 != 0x80) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (apdu.data.size == 0) {
            status(verificationHeld() ? 0x9000 : 0x63C3, response,
                   responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (apdu.data.size != 8) {
            status(0x6700, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (!userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }
        verified_ = true;
        verifiedAtMilliseconds_ = diagnostics_.uptimeMilliseconds();
        status(0x9000, response, responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0x47) {
        if (apdu.cla != 0x00 || apdu.parameter1 != 0x00 ||
            (apdu.parameter2 != 0x9A && apdu.parameter2 != 0x9D)) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (!parseKeyGenerationTemplate(apdu.data)) {
            status(0x6A80, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        // A factory board has no identity and no enrolled finger, so demanding
        // presence here would make it unprovisionable. The window closes the
        // moment PUT DATA stores the matching certificate.
        if (provisioned() && !userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }

        uint8_t publicKey[65];
        size_t publicKeyLength = 0;
        if (!credential_.generateKeyP256(static_cast<Slot>(apdu.parameter2),
                                         publicKey, sizeof(publicKey),
                                         publicKeyLength) ||
            publicKeyLength != sizeof(publicKey) || publicKey[0] != 0x04) {
            status(0x6F00, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        verified_ = false;

        uint8_t encoded[72];
        Writer writer(encoded, sizeof(encoded));
        if (!writer.byte(0x7F) || !writer.byte(0x49) ||
            !writer.length(2 + sizeof(publicKey)) || !writer.byte(0x86) ||
            !writer.length(sizeof(publicKey)) ||
            !writer.bytes(publicKey, sizeof(publicKey))) {
            status(0x6F00, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        sendData(encoded, writer.size(), apdu.expectedLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0xDB) {
        if (apdu.cla != 0x00 || apdu.parameter1 != 0x3F ||
            apdu.parameter2 != 0xFF) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }

        Bytes tagList{nullptr, 0};
        Bytes object{nullptr, 0};
        if (!parsePutDataObject(apdu.data, tagList, object)) {
            status(0x6A80, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        constexpr uint8_t certificateTag[] = {0x5F, 0xC1, 0x05};
        constexpr uint8_t keyManagementTag[] = {0x5F, 0xC1, 0x0B};
        const bool keyManagementObject =
            tagList.size == sizeof(keyManagementTag) &&
            std::memcmp(tagList.data, keyManagementTag,
                        sizeof(keyManagementTag)) == 0;
        if (!keyManagementObject &&
            (tagList.size != sizeof(certificateTag) ||
             std::memcmp(tagList.data, certificateTag,
                         sizeof(certificateTag)) != 0)) {
            status(0x6A82, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        Bytes certificate{nullptr, 0};
        if (!parseCertificateContent(object, certificate)) {
            status(0x6A80, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (provisioned() && !userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }
        if (!credential_.storeCertificate(keyManagementObject
                                              ? Slot::keyManagement
                                              : Slot::authentication,
                                          certificate)) {
            status(0x6A84, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        status(0x9000, response, responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0x87) {
        if (apdu.cla != 0x00 || apdu.parameter1 != 0x11 ||
            (apdu.parameter2 != 0x9A && apdu.parameter2 != 0x9D)) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }

        // Slot 9D: ECDH. macOS uses it at login to unwrap the keychain
        // password, so it sits behind the same gate as a signature, and one
        // verified touch buys one private-key operation in either slot.
        if (apdu.parameter2 == 0x9D) {
            Bytes peerPoint{nullptr, 0};
            if (!parseKeyAgreementTemplate(apdu.data, peerPoint)) {
                status(0x6A80, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            const Bytes keyManagement =
                credential_.certificateDer(Slot::keyManagement);
            if (keyManagement.data == nullptr || keyManagement.size == 0) {
                status(0x6A88, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            if (!verificationHeld() && !userPresent) {
                return TransceiveStatus::userPresenceRequired;
            }
            // Spent here, whether or not the point turns out to be usable.
            verified_ = false;

            uint8_t encoded[4 + 32] = {0x7C, 0x22, 0x82, 0x20};
            size_t secretLength = 0;
            if (!credential_.agreeP256(peerPoint, encoded + 4, 32,
                                       secretLength) ||
                secretLength != 32) {
                wipe(encoded, sizeof(encoded));
                status(0x6A80, response, responseCapacity, responseLength);
                return TransceiveStatus::complete;
            }
            sendData(encoded, sizeof(encoded), apdu.expectedLength);
            wipe(encoded, sizeof(encoded));
            return TransceiveStatus::complete;
        }

        Bytes digest{nullptr, 0};
        if (!parseAuthenticationTemplate(apdu.data, digest)) {
            status(0x6A80, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        // Answer before the presence gate: an unprovisioned board would
        // otherwise hold the request open for a fingerprint it can only spend
        // on a key that does not exist.
        if (!provisioned()) {
            status(0x6A88, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (!verificationHeld() && !userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }

        uint8_t signature[80];
        size_t signatureLength = 0;
        if (!credential_.signP256Sha256(digest, signature, sizeof(signature),
                                        signatureLength) ||
            signatureLength == 0 || signatureLength > sizeof(signature)) {
            status(0x6F00, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        verified_ = false;

        uint8_t encoded[96];
        Writer writer(encoded, sizeof(encoded));
        const size_t responseTlvLength = signatureLength +
                                         (signatureLength < 0x80 ? 2 : 3);
        if (!writer.byte(0x7C) || !writer.length(responseTlvLength) ||
            !writer.byte(0x82) || !writer.length(signatureLength) ||
            !writer.bytes(signature, signatureLength)) {
            status(0x6F00, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        sendData(encoded, writer.size(), apdu.expectedLength);
        return TransceiveStatus::complete;
    }

    // APPROVE. The one instruction nothing pays for in advance: a VERIFY
    // that a touch answered, the agreement that touch bought and a touch the
    // idle ring took are all for logging in, and this path reads none of
    // them. The gate behind it counts only a finger that landed after the
    // question (demandsFreshTouch), and what it buys is this one signature.
    //
    // The card builds and hashes the message itself. GENERAL AUTHENTICATE
    // signs any digest a host hands it with the same key, so the signature
    // proves a touch only to a verifier that drew the number at random and
    // showed it to nobody else.
    if (apdu.instruction == kApproveInstruction) {
        if (apdu.cla != 0x80 || apdu.parameter1 != kApprovalAdministrator ||
            apdu.parameter2 != 0x00) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (apdu.data.size != kApprovalNumberSize) {
            status(0x6700, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        // Before the gate, as for a signature: no key, nothing to wait for.
        if (!provisioned()) {
            status(0x6A88, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (!userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }

        // The label goes in with its terminating zero.
        uint8_t message[sizeof(kApprovalLabel) + 1 + kApprovalNumberSize];
        std::memcpy(message, kApprovalLabel, sizeof(kApprovalLabel));
        message[sizeof(kApprovalLabel)] = apdu.parameter1;
        std::memcpy(message + sizeof(kApprovalLabel) + 1, apdu.data.data,
                    kApprovalNumberSize);
        uint8_t signature[80];
        size_t signatureLength = 0;
        if (!credential_.signMessageP256Sha256({message, sizeof(message)},
                                               signature, sizeof(signature),
                                               signatureLength) ||
            signatureLength == 0 || signatureLength > sizeof(signature)) {
            status(0x6F00, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        sendData(signature, signatureLength, apdu.expectedLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0xE1) {
        if (apdu.cla != 0x80 || apdu.parameter1 != 0x00 ||
            apdu.parameter2 != 0x00) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        // An empty sensor can never produce a match, so the first finger has
        // to enroll unauthenticated. Emptying it needs the sensor password.
        // Empty has to be something the sensor reported: an unknown count is
        // treated as a full library, because the alternative lets a sensor
        // that failed to answer at boot hand out free enrollment.
        if (!libraryKnownEmpty() && !userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }
        uint8_t stage = 0;
        if (!diagnostics_.enrollStep(stage)) {
            status(0x6D00, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        sendData(&stage, 1, apdu.expectedLength);
        return TransceiveStatus::complete;
    }

    // ARM RING. Not presence-gated: it releases nothing and reveals nothing,
    // it only asks the board to look at its own sensor for a while. The board
    // caps the duration, so a host cannot turn it into a permanent load.
    if (apdu.instruction == 0xE3) {
        if (apdu.cla != 0x80 || apdu.parameter1 != 0x00 ||
            apdu.parameter2 != 0x00 || apdu.data.size != 1) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        status(diagnostics_.armRing(apdu.data.data[0]) ? 0x9000 : 0x6D00,
               response, responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0xE2) {
        if (apdu.cla != 0x80 || apdu.parameter1 != 0x00 ||
            apdu.parameter2 != 0x00) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        // Forgetting is how a finger the sensor no longer recognises gets
        // replaced, so demanding a match from an already empty library would
        // make the recovery it exists for impossible. There is also nothing
        // there to protect.
        if (libraryKnownEmpty()) {
            status(0x9000, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (!userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }
        status(diagnostics_.forgetFingerprints() ? 0x9000 : 0x6D00, response,
               responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    if (apdu.instruction == 0xF0) {
        if (apdu.cla != 0x80 || apdu.parameter1 != 0x00 ||
            apdu.parameter2 != 0x00) {
            status(0x6A86, response, responseCapacity, responseLength);
            return TransceiveStatus::complete;
        }
        if (!userPresent) {
            return TransceiveStatus::userPresenceRequired;
        }
        status(diagnostics_.enterDownloadMode() ? 0x9000 : 0x6D00, response,
               responseCapacity, responseLength);
        return TransceiveStatus::complete;
    }

    status(0x6D00, response, responseCapacity, responseLength);
    return TransceiveStatus::complete;
}

// A verified touch is good for one signature and for a bounded time. Checking
// it is also what retires a stale one.
bool PivApplet::verificationHeld() {
    if (verified_ && diagnostics_.uptimeMilliseconds() -
                             verifiedAtMilliseconds_ >=
                         kVerifiedValidMilliseconds) {
        verified_ = false;
    }
    return verified_;
}

bool PivApplet::provisioned() const {
    const Bytes certificate = credential_.certificateDer(Slot::authentication);
    return certificate.data != nullptr && certificate.size != 0;
}

RateLimiter::RateLimiter(uint32_t failureThreshold,
                         uint64_t baseLockoutMilliseconds,
                         uint64_t maximumLockoutMilliseconds)
    : failureThreshold_(failureThreshold),
      baseLockoutMilliseconds_(baseLockoutMilliseconds),
      maximumLockoutMilliseconds_(maximumLockoutMilliseconds) {}

bool RateLimiter::locked(uint64_t nowMilliseconds) const {
    return nowMilliseconds < lockedUntilMilliseconds_;
}

uint64_t RateLimiter::lockoutMillisecondsRemaining(
    uint64_t nowMilliseconds) const {
    return locked(nowMilliseconds) ? lockedUntilMilliseconds_ - nowMilliseconds
                                   : 0;
}

uint32_t RateLimiter::consecutiveFailures() const {
    return consecutiveFailures_;
}

uint32_t RateLimiter::lockoutCount() const {
    return lockoutCount_;
}

// The clock restarts at zero on every power cycle, so a restored lockout is
// re-armed in full rather than resumed: unplugging the device must never be a
// way to shorten it.
void RateLimiter::restore(uint32_t consecutiveFailures, uint32_t lockoutCount,
                          uint64_t nowMilliseconds) {
    consecutiveFailures_ = consecutiveFailures;
    lockoutCount_ = lockoutCount;
    lockedUntilMilliseconds_ =
        lockoutCount_ == 0 ? 0
                           : nowMilliseconds + lockoutDuration(lockoutCount_ - 1);
}

void RateLimiter::recordFailure(uint64_t nowMilliseconds) {
    if (locked(nowMilliseconds)) {
        return;
    }
    if (++consecutiveFailures_ < failureThreshold_) {
        return;
    }
    consecutiveFailures_ = 0;
    lockedUntilMilliseconds_ = nowMilliseconds + lockoutDuration(lockoutCount_);
    ++lockoutCount_;
}

void RateLimiter::recordSuccess() {
    consecutiveFailures_ = 0;
    lockoutCount_ = 0;
    lockedUntilMilliseconds_ = 0;
}

uint64_t RateLimiter::lockoutDuration(uint32_t lockoutCount) const {
    return std::min(maximumLockoutMilliseconds_,
                    baseLockoutMilliseconds_
                        << std::min<uint32_t>(lockoutCount, 20));
}

AttemptLedger::AttemptLedger(RateLimiter &limiter, LimiterStore &store)
    : limiter_(limiter), store_(store) {}

bool AttemptLedger::charge(uint64_t nowMilliseconds) {
    if (limiter_.locked(nowMilliseconds)) {
        return false;
    }
    limiter_.recordFailure(nowMilliseconds);
    return store_.save(limiter_.consecutiveFailures(),
                       limiter_.lockoutCount());
}

void AttemptLedger::matched() {
    limiter_.recordSuccess();
    store_.save(limiter_.consecutiveFailures(), limiter_.lockoutCount());
}

FreshTouch::FreshTouch(uint8_t emptyReadings)
    : emptyReadings_(emptyReadings) {}

bool FreshTouch::observe(bool fingerPresent) {
    if (fingerPresent) {
        emptyRun_ = 0;
        return seenEmpty_;
    }
    if (!seenEmpty_ && ++emptyRun_ >= emptyReadings_) {
        seenEmpty_ = true;
    }
    return false;
}

EarlyTouch::EarlyTouch(uint64_t validMilliseconds)
    : validMilliseconds_(validMilliseconds) {}

void EarlyTouch::record(uint64_t nowMilliseconds) {
    expiresAtMilliseconds_ = nowMilliseconds + validMilliseconds_;
}

bool EarlyTouch::held(uint64_t nowMilliseconds) const {
    return expiresAtMilliseconds_ != 0 &&
           nowMilliseconds < expiresAtMilliseconds_;
}

uint64_t EarlyTouch::millisecondsRemaining(uint64_t nowMilliseconds) const {
    return held(nowMilliseconds) ? expiresAtMilliseconds_ - nowMilliseconds : 0;
}

bool EarlyTouch::maySpend(uint8_t instruction) {
    return instruction == 0x20 || instruction == 0x87;
}

bool EarlyTouch::spend(uint8_t instruction, uint64_t nowMilliseconds) {
    if (!maySpend(instruction) || !held(nowMilliseconds)) {
        return false;
    }
    expiresAtMilliseconds_ = 0;
    ++gates_;
    return true;
}

void EarlyTouch::clear() { expiresAtMilliseconds_ = 0; }

uint32_t EarlyTouch::gates() const { return gates_; }

bool Autotype::arm(uint8_t seconds, uint64_t nowMilliseconds, bool toWake) {
    const uint64_t capped =
        seconds < kMaximumAutotypeSeconds ? seconds : kMaximumAutotypeSeconds;
    const bool woken = nowMilliseconds < wokenUntilMilliseconds_;
    if (capped == 0) {
        armedUntilMilliseconds_ = 0;
        forgetWoken();
        return false;
    }
    if (woken && !toWake) {
        // The match that woke the Mac is the one this arming is for, so the
        // arming is spent on it and leaves nothing behind. The host's word
        // is given once; after it the retype timer owns the match.
        armedUntilMilliseconds_ = 0;
        if (retypeAtMilliseconds_ != 0) {
            return false;
        }
        retypeAtMilliseconds_ = nowMilliseconds + kRetypeMilliseconds;
        retypesLeft_ = kMaximumRetypes;
        ++emissions_;
        return true;
    }
    armedUntilMilliseconds_ = nowMilliseconds + capped * 1000;
    toWake_ = toWake;
    return false;
}

uint8_t Autotype::secondsRemaining(uint64_t nowMilliseconds) const {
    if (nowMilliseconds >= armedUntilMilliseconds_) {
        return 0;
    }
    return static_cast<uint8_t>(
        (armedUntilMilliseconds_ - nowMilliseconds + 999) / 1000);
}

bool Autotype::take(uint64_t nowMilliseconds) {
    if (nowMilliseconds >= armedUntilMilliseconds_) {
        return false;
    }
    armedUntilMilliseconds_ = 0;
    if (toWake_) {
        // Nothing is typed yet, so nothing is counted yet.
        wokeHost(nowMilliseconds);
    } else {
        ++emissions_;
    }
    return true;
}

bool Autotype::wakes() const { return toWake_; }

void Autotype::wokeHost(uint64_t nowMilliseconds) {
    wokenUntilMilliseconds_ = nowMilliseconds + kWokenMatchMilliseconds;
    retypeAtMilliseconds_ = 0;
    retypesLeft_ = 0;
}

bool Autotype::retype(uint64_t nowMilliseconds) {
    if (nowMilliseconds >= wokenUntilMilliseconds_ ||
        retypeAtMilliseconds_ == 0 || retypesLeft_ == 0 ||
        nowMilliseconds < retypeAtMilliseconds_) {
        return false;
    }
    --retypesLeft_;
    retypeAtMilliseconds_ = nowMilliseconds + kRetypeMilliseconds;
    ++emissions_;
    return true;
}

void Autotype::hostActed() { forgetWoken(); }

void Autotype::forgetWoken() {
    wokenUntilMilliseconds_ = 0;
    retypeAtMilliseconds_ = 0;
    retypesLeft_ = 0;
}

uint32_t Autotype::emissions() const { return emissions_; }

void Autotype::wakeReport(bool pressed, uint8_t report[8]) {
    std::memset(report, 0, 8);
    report[0] = pressed ? 0x02 : 0x00;  // Left Shift
}

void Autotype::report(size_t index, uint8_t report[8]) {
    // Return, the same key position under every layout. No digits: each one
    // draws a dot in the PIN field, and macOS takes the field empty.
    static_assert(kReportCount == 2);
    std::memset(report, 0, 8);
    if (index == 0) {
        report[2] = 0x28;
    }
}

void hedgedNonceSeed(const uint8_t randomness[32], const uint8_t scalar[32],
                     const uint8_t digest[32],
                     uint8_t seed[kHedgedNonceSeedSize]) {
    // The order of the P-256 group.
    static constexpr uint8_t kOrder[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
        0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    };
    std::memset(seed, 0, kHedgedNonceSeedSize);
    std::memcpy(seed, randomness, 32);
    std::memcpy(seed + 95, scalar, 32);

    // bits2octets: a digest is below twice the order, so one subtraction
    // reduces it. The digest is public, and branching on it leaks nothing.
    uint8_t *reduced = seed + 159;
    std::memcpy(reduced, digest, 32);
    if (std::memcmp(digest, kOrder, 32) >= 0) {
        int borrow = 0;
        for (int index = 31; index >= 0; --index) {
            const int difference = reduced[index] - kOrder[index] - borrow;
            reduced[index] = static_cast<uint8_t>(difference);
            borrow = difference < 0 ? 1 : 0;
        }
    }
}

WakeLine::WakeLine(bool touchedLevel) : touchedLevel_(touchedLevel) {}

void WakeLine::observe(bool level) { seen_ |= level ? 0b10 : 0b01; }

bool WakeLine::usable() const { return seen_ == 0b11; }

bool WakeLine::touched(bool level) const {
    return usable() && level == touchedLevel_;
}

}  // namespace deskid
