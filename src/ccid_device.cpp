// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

#include "ccid_device.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>

#include "device/usbd_pvt.h"
#include "esp_check.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"

#ifndef DESKID_USB_VID
#error "DESKID_USB_VID must be assigned to an authorized USB vendor ID"
#endif

#ifndef DESKID_USB_PID
#error "DESKID_USB_PID must be assigned to this product"
#endif

#if defined(DESKID_PRODUCTION) && \
    (DESKID_USB_VID == 0xCAFE || DESKID_USB_PID == 0xD15D)
#error "Production builds require an authorized VID/PID in platformio.ini"
#endif

// A sdkconfig generated before the HID interfaces existed keeps its own zero
// and builds a device whose descriptors name drivers that are not there.
#if CFG_TUD_HID != 2
#error "CONFIG_TINYUSB_HID_COUNT must be 2: delete sdkconfig.<env> to apply sdkconfig.defaults"
#endif

namespace deskid {
namespace {

constexpr uint8_t kInterfaceNumber = 0;
constexpr uint8_t kBulkOutEndpoint = 0x01;
constexpr uint8_t kBulkInEndpoint = 0x81;
// TinyUSB numbers HID instances in the order their interfaces appear.
constexpr uint8_t kKeyboardInterface = 1;
constexpr uint8_t kKeyboardInstance = 0;
constexpr uint8_t kKeyboardEndpoint = 0x82;
constexpr uint8_t kArmingInterface = 2;
constexpr uint8_t kArmingInstance = 1;
constexpr uint8_t kArmingEndpoint = 0x83;
constexpr uint8_t kArmAutotypeCommand = 0x01;
// The same request for a display that is asleep: a match taps the wake key
// and the digits wait for the next ordinary arming. See deskid::Autotype.
constexpr uint8_t kArmToWakeCommand = 0x02;
// Fourth byte of the report a host reads back.
constexpr uint8_t kStatusWakes = 0x01;           // understands kArmToWakeCommand
constexpr uint8_t kStatusWatchesForFree = 0x02;  // the wake line is trusted
constexpr size_t kEndpointSize = 64;
constexpr size_t kHeaderSize = 10;
constexpr size_t kMaximumMessageLength = 2048;
constexpr uint16_t kPendingFlag = 0x100;
constexpr uint16_t kToWakeFlag = 0x200;

enum MessageType : uint8_t {
    kPcToReaderPowerOn = 0x62,
    kPcToReaderPowerOff = 0x63,
    kPcToReaderGetSlotStatus = 0x65,
    kPcToReaderXfrBlock = 0x6F,
    kPcToReaderGetParameters = 0x6C,
    kPcToReaderResetParameters = 0x6D,
    kPcToReaderSetParameters = 0x61,
    kPcToReaderEscape = 0x6B,
    kPcToReaderSecure = 0x69,
    kPcToReaderMechanical = 0x71,
    kPcToReaderAbort = 0x72,
    kPcToReaderSetDataRateAndClock = 0x73,
    kReaderToPcDataBlock = 0x80,
    kReaderToPcSlotStatus = 0x81,
    kReaderToPcParameters = 0x82,
    kReaderToPcEscape = 0x83,
    kReaderToPcDataRateAndClock = 0x84,
};

// CCID error byte values. The error field's meaning depends on the
// accompanying status byte, so kNoError and kCommandNotSupported both
// correctly map to 0x00 — they appear in different status contexts.
enum CcidError : uint8_t {
    kNoError = 0x00,
    kCommandNotSupported = 0x00,
    kBadLength = 0x01,
    kBadSlot = 0x05,
    kSlotBusy = 0xE0,
};

constexpr uint8_t kCommandSucceededActive = 0x00;
constexpr uint8_t kCommandSucceededInactive = 0x01;
constexpr uint8_t kCommandFailedActive = 0x40;
constexpr uint8_t kCommandFailedInactive = 0x41;
constexpr uint8_t kCommandTimeExtensionActive = 0x80;

constexpr tusb_desc_device_t kDeviceDescriptor = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_UNSPECIFIED,
    .bDeviceSubClass = 0,
    .bDeviceProtocol = 0,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = DESKID_USB_VID,
    .idProduct = DESKID_USB_PID,
    .bcdDevice = 0x0110,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

// Eight bytes: modifiers, a reserved byte and six keys. No report ID and no
// boot subclass, since nothing here has to type into firmware setup screens.
constexpr uint8_t kKeyboardReportDescriptor[] = {
    TUD_HID_REPORT_DESC_KEYBOARD()};

// The arming interface is its own HID interface on a vendor usage page, not a
// second collection on the keyboard. macOS folds every collection of one
// interface into a single device, and opening a device whose first usage is a
// keyboard needs the Input Monitoring permission. A vendor device does not.
//
// Feature report, host to board: 0x01, seconds, or 0x02, seconds when the
// display is asleep. Board to host: 0x01, seconds the arming has left,
// emissions since power-up, status bits. The input report exists because a
// HID interface must have an interrupt IN endpoint; it is never sent.
constexpr uint8_t kArmingReportDescriptor[] = {
    0x06, 0x00, 0xFF,  // Usage Page (vendor 0xFF00)
    0x09, 0x01,        // Usage (1)
    0xA1, 0x01,        // Collection (Application)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x08,        //   Report Count (8)
    0x09, 0x02,        //   Usage (2)
    0xB1, 0x02,        //   Feature (Data, Variable, Absolute)
    0x09, 0x03,        //   Usage (3)
    0x81, 0x02,        //   Input (Data, Variable, Absolute)
    0xC0,              // End Collection
};
constexpr size_t kArmingReportSize = 8;

constexpr uint16_t kConfigurationLength = 86 + 2 * TUD_HID_DESC_LEN;

// Device class 0 and no interface association: CCID and HID are one interface
// each, which is how a YubiKey presents the same three functions. Four IN
// endpoints with endpoint 0, one under what the ESP32-S3 can keep active.
constexpr uint8_t kConfigurationDescriptor[] = {
    // Bus powered, and allowed to wake a sleeping host: a touch has to be
    // able to do what a key press on a keyboard does.
    9, TUSB_DESC_CONFIGURATION, U16_TO_U8S_LE(kConfigurationLength), 3, 1, 0,
    0x80 | TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100,
    9, TUSB_DESC_INTERFACE, kInterfaceNumber, 0, 2, TUSB_CLASS_SMART_CARD, 0, 0, 4,
    0x36, TUSB_DESC_FUNCTIONAL,
    0x10, 0x01,
    0x00,
    0x07,
    0x02, 0x00, 0x00, 0x00,
    0xA0, 0x0F, 0x00, 0x00,
    0xA0, 0x0F, 0x00, 0x00,
    0x01,
    0x00, 0xC2, 0x01, 0x00,
    0x00, 0xC2, 0x01, 0x00,
    0x01,
    0xFE, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xFE, 0x00, 0x04, 0x00,
    0x00, 0x08, 0x00, 0x00,
    0x00,
    0x00,
    0x00, 0x00,
    0x01,  // bPINSupport: PIN verification on the reader — the fingerprint ring
    0x01,
    7, TUSB_DESC_ENDPOINT, kBulkOutEndpoint, TUSB_XFER_BULK,
    static_cast<uint8_t>(kEndpointSize), 0, 0,
    7, TUSB_DESC_ENDPOINT, kBulkInEndpoint, TUSB_XFER_BULK,
    static_cast<uint8_t>(kEndpointSize), 0, 0,
    TUD_HID_DESCRIPTOR(kKeyboardInterface, 0, HID_ITF_PROTOCOL_NONE,
                       sizeof(kKeyboardReportDescriptor), kKeyboardEndpoint,
                       8, 10),
    TUD_HID_DESCRIPTOR(kArmingInterface, 0, HID_ITF_PROTOCOL_NONE,
                       sizeof(kArmingReportDescriptor), kArmingEndpoint,
                       kArmingReportSize, 10),
};

static_assert(sizeof(kConfigurationDescriptor) == kConfigurationLength);

constexpr uint8_t kAtr[] = {0x3B, 0x80, 0x01, 0x81};
constexpr uint8_t kT1Parameters[] = {0x11, 0x10, 0x00, 0x4D,
                                     0x00, 0xFE, 0x00};
constexpr uint8_t kClockAndDataRate[] = {0xA0, 0x0F, 0x00, 0x00,
                                         0x00, 0xC2, 0x01, 0x00};

alignas(4) uint8_t s_outPacket[kEndpointSize];
alignas(4) uint8_t s_receivedMessage[kMaximumMessageLength];
alignas(4) uint8_t s_transmitMessage[kMaximumMessageLength];
CcidRequest s_requestBuffer;
// The USB task fills the buffer and the main task empties it, and a host that
// aborts and resends can make those overlap.
portMUX_TYPE s_requestLock = portMUX_INITIALIZER_UNLOCKED;
size_t s_receivedLength = 0;
size_t s_expectedLength = 0;
uint8_t s_rootPort = 0;
uint8_t s_interface = 0xFF;
uint8_t s_outEndpoint = 0;
uint8_t s_inEndpoint = 0;
bool s_cardPowered = false;
QueueHandle_t s_requestQueue = nullptr;
SemaphoreHandle_t s_transmitAvailable = nullptr;
std::atomic<uint16_t> s_pendingRequest{0};
std::atomic<uint16_t> s_abortedRequest{0};
// kPendingFlag marks a request the main task has not taken yet; the low byte
// is the seconds asked for, and zero is a real request: it disarms.
// kToWakeFlag marks a request made for a display that is asleep.
std::atomic<uint16_t> s_autotypeArm{0};
std::atomic<uint8_t> s_autotypeSecondsRemaining{0};
std::atomic<uint8_t> s_autotypeEmissions{0};
std::atomic<uint8_t> s_autotypeStatus{0};
std::atomic<uint32_t> s_powerEpoch{0};
std::atomic<uint32_t> s_secureRequests{0};
char s_serialNumber[13] = {};
const char kLanguage[] = {0x09, 0x04};
const char *s_strings[] = {
    kLanguage,
    "DeskID",
    "DeskID Biometric PIV",
    s_serialNumber,
    "CCID Smart Card",
};

uint32_t readLittleEndian32(const uint8_t *value) {
    return static_cast<uint32_t>(value[0]) |
           (static_cast<uint32_t>(value[1]) << 8) |
           (static_cast<uint32_t>(value[2]) << 16) |
           (static_cast<uint32_t>(value[3]) << 24);
}

void writeLittleEndian32(uint8_t *destination, uint32_t value) {
    destination[0] = static_cast<uint8_t>(value);
    destination[1] = static_cast<uint8_t>(value >> 8);
    destination[2] = static_cast<uint8_t>(value >> 16);
    destination[3] = static_cast<uint8_t>(value >> 24);
}

bool sendResponse(uint8_t type, uint8_t slot, uint8_t sequence,
                  uint8_t responseStatus, uint8_t error,
                  uint8_t responseSpecific, const uint8_t *data,
                  size_t dataLength, TickType_t waitTicks) {
    if (dataLength > kMaximumMessageLength - kHeaderSize ||
        s_transmitAvailable == nullptr || s_inEndpoint == 0 ||
        xSemaphoreTake(s_transmitAvailable, waitTicks) != pdTRUE) {
        return false;
    }

    s_transmitMessage[0] = type;
    writeLittleEndian32(s_transmitMessage + 1,
                        static_cast<uint32_t>(dataLength));
    s_transmitMessage[5] = slot;
    s_transmitMessage[6] = sequence;
    s_transmitMessage[7] = responseStatus;
    s_transmitMessage[8] = error;
    s_transmitMessage[9] = responseSpecific;
    if (dataLength != 0) {
        std::memcpy(s_transmitMessage + kHeaderSize, data, dataLength);
    }

    const bool claimed = usbd_edpt_claim(s_rootPort, s_inEndpoint);
    if (!claimed ||
        !usbd_edpt_xfer(s_rootPort, s_inEndpoint, s_transmitMessage,
                        static_cast<uint16_t>(kHeaderSize + dataLength),
                        false)) {
        if (claimed) {
            usbd_edpt_release(s_rootPort, s_inEndpoint);
        }
        xSemaphoreGive(s_transmitAvailable);
        return false;
    }
    return true;
}

void sendSlotFailure(uint8_t slot, uint8_t sequence, uint8_t error) {
    sendResponse(kReaderToPcSlotStatus, slot, sequence,
                 s_cardPowered ? kCommandFailedActive : kCommandFailedInactive,
                 error, s_cardPowered ? 0x00 : 0x01, nullptr, 0, 0);
}

void armOutEndpoint() {
    if (s_outEndpoint != 0) {
        usbd_edpt_xfer(s_rootPort, s_outEndpoint, s_outPacket,
                       sizeof(s_outPacket), false);
    }
}

void processMessage(const uint8_t *message, size_t length) {
    if (length < kHeaderSize) {
        return;
    }

    const uint8_t type = message[0];
    const uint32_t bodyLength = readLittleEndian32(message + 1);
    const uint8_t slot = message[5];
    const uint8_t sequence = message[6];
    if (slot != 0) {
        sendSlotFailure(slot, sequence, kBadSlot);
        return;
    }
    if (bodyLength != length - kHeaderSize) {
        sendSlotFailure(slot, sequence, kBadLength);
        return;
    }

    switch (type) {
        case kPcToReaderPowerOn:
            s_cardPowered = true;
            ++s_powerEpoch;
            sendResponse(kReaderToPcDataBlock, slot, sequence,
                         kCommandSucceededActive, kNoError, 0, kAtr,
                         sizeof(kAtr), 0);
            break;

        case kPcToReaderPowerOff:
            s_cardPowered = false;
            s_pendingRequest.store(0);
            ++s_powerEpoch;
            sendResponse(kReaderToPcSlotStatus, slot, sequence,
                         kCommandSucceededInactive, kNoError, 0x01, nullptr, 0,
                         0);
            break;

        case kPcToReaderGetSlotStatus:
            sendResponse(kReaderToPcSlotStatus, slot, sequence,
                         s_cardPowered ? kCommandSucceededActive
                                       : kCommandSucceededInactive,
                         kNoError, s_cardPowered ? 0x00 : 0x01, nullptr, 0, 0);
            break;

        case kPcToReaderGetParameters:
        case kPcToReaderResetParameters:
        case kPcToReaderSetParameters:
            sendResponse(kReaderToPcParameters, slot, sequence,
                         s_cardPowered ? kCommandSucceededActive
                                       : kCommandSucceededInactive,
                         kNoError, 0x01, kT1Parameters,
                         sizeof(kT1Parameters), 0);
            break;

        case kPcToReaderSetDataRateAndClock:
            sendResponse(kReaderToPcDataRateAndClock, slot, sequence,
                         s_cardPowered ? kCommandSucceededActive
                                       : kCommandSucceededInactive,
                         kNoError, 0, kClockAndDataRate,
                         sizeof(kClockAndDataRate), 0);
            break;

        // PC_to_RDR_Secure is how a host asks a reader with a PIN pad to
        // collect the PIN itself and send the VERIFY. DeskID's "pad" is the
        // fingerprint ring: the APDU template at the end of the message is
        // handed to the applet exactly like an XfrBlock, whose VERIFY path
        // waits for a match and ignores the digits. The response is the same
        // RDR_to_PC_DataBlock either way, so the rest of the pipeline does
        // not know the difference. Only verification (bPINOperation 0) is
        // supported; a PIN modification has nothing to modify.
        case kPcToReaderSecure:
        case kPcToReaderXfrBlock: {
            const uint8_t *apdu = message + kHeaderSize;
            size_t apduLength = bodyLength;
            if (type == kPcToReaderSecure) {
                s_secureRequests.fetch_add(1);
                constexpr size_t kPinVerifyStructure = 15;  // bPINOperation + PIN verification data
                if (bodyLength < kPinVerifyStructure + 5 || apdu[0] != 0x00) {
                    sendResponse(kReaderToPcDataBlock, slot, sequence,
                                 s_cardPowered ? kCommandFailedActive
                                               : kCommandFailedInactive,
                                 kCommandNotSupported, 0, nullptr, 0, 0);
                    break;
                }
                apdu += kPinVerifyStructure;
                apduLength -= kPinVerifyStructure;
            }
            if (!s_cardPowered) {
                sendResponse(kReaderToPcDataBlock, slot, sequence,
                             kCommandFailedInactive, kNoError, 0, nullptr, 0,
                             0);
                break;
            }
            // A request that was aborted or powered off may still be waiting
            // in the queue for the main task. Its buffer is not ours to reuse
            // until it has been collected, or that task would run this APDU
            // under the old one's notification.
            if (apduLength > CcidRequest::kMaximumApduLength ||
                s_pendingRequest.load() != 0 ||
                uxQueueMessagesWaiting(s_requestQueue) != 0) {
                sendResponse(kReaderToPcDataBlock, slot, sequence,
                             kCommandFailedActive,
                             apduLength > CcidRequest::kMaximumApduLength
                                 ? kBadLength
                                 : kSlotBusy,
                             0, nullptr, 0, 0);
                break;
            }

            portENTER_CRITICAL(&s_requestLock);
            s_requestBuffer.slot = slot;
            s_requestBuffer.sequence = sequence;
            s_requestBuffer.powerEpoch = s_powerEpoch.load();
            s_requestBuffer.apduLength = apduLength;
            std::memcpy(s_requestBuffer.apdu, apdu, apduLength);
            portEXIT_CRITICAL(&s_requestLock);
            s_abortedRequest.store(0);
            s_pendingRequest.store(kPendingFlag | sequence);
            constexpr uint8_t notification = 1;
            if (xQueueSend(s_requestQueue, &notification, 0) != pdTRUE) {
                s_pendingRequest.store(0);
                sendResponse(kReaderToPcDataBlock, slot, sequence,
                             kCommandFailedActive, kSlotBusy, 0, nullptr, 0, 0);
            }
            break;
        }

        case kPcToReaderAbort:
            if (s_pendingRequest.load() == (kPendingFlag | sequence)) {
                s_abortedRequest.store(kPendingFlag | sequence);
                s_pendingRequest.store(0);
            }
            sendResponse(kReaderToPcSlotStatus, slot, sequence,
                         s_cardPowered ? kCommandSucceededActive
                                       : kCommandSucceededInactive,
                         kNoError, s_cardPowered ? 0x00 : 0x01, nullptr, 0, 0);
            break;

        case kPcToReaderEscape:
            sendResponse(kReaderToPcEscape, slot, sequence,
                         s_cardPowered ? kCommandFailedActive
                                       : kCommandFailedInactive,
                         kCommandNotSupported, 0, nullptr, 0, 0);
            break;

        case kPcToReaderMechanical:
        default:
            sendSlotFailure(slot, sequence, kCommandNotSupported);
            break;
    }
}

void resetDriver(uint8_t rootPort) {
    s_rootPort = rootPort;
    s_interface = 0xFF;
    s_outEndpoint = 0;
    s_inEndpoint = 0;
    s_receivedLength = 0;
    s_expectedLength = 0;
    s_cardPowered = false;
    s_pendingRequest.store(0);
    s_abortedRequest.store(0);
    ++s_powerEpoch;
    if (s_requestQueue != nullptr) {
        xQueueReset(s_requestQueue);
    }
    if (s_transmitAvailable != nullptr) {
        xSemaphoreGive(s_transmitAvailable);
    }
}

uint16_t openDriver(uint8_t rootPort,
                    const tusb_desc_interface_t *interfaceDescriptor,
                    uint16_t maximumLength) {
    if (interfaceDescriptor->bInterfaceClass != TUSB_CLASS_SMART_CARD) {
        return 0;
    }

    s_rootPort = rootPort;
    s_interface = interfaceDescriptor->bInterfaceNumber;
    const uint8_t *end = reinterpret_cast<const uint8_t *>(interfaceDescriptor) +
                         maximumLength;
    const uint8_t *descriptor = tu_desc_next(interfaceDescriptor);
    while (tu_desc_in_bounds(descriptor, end)) {
        const uint8_t type = tu_desc_type(descriptor);
        if (type == TUSB_DESC_INTERFACE ||
            type == TUSB_DESC_INTERFACE_ASSOCIATION) {
            break;
        }
        if (type == TUSB_DESC_ENDPOINT) {
            const auto *endpoint =
                reinterpret_cast<const tusb_desc_endpoint_t *>(descriptor);
            if (!usbd_edpt_open(rootPort, endpoint)) {
                return 0;
            }
            if (tu_edpt_dir(endpoint->bEndpointAddress) == TUSB_DIR_IN) {
                s_inEndpoint = endpoint->bEndpointAddress;
            } else {
                s_outEndpoint = endpoint->bEndpointAddress;
            }
        }
        descriptor = tu_desc_next(descriptor);
    }

    if (s_outEndpoint == 0 || s_inEndpoint == 0) {
        return 0;
    }
    armOutEndpoint();
    return static_cast<uint16_t>(descriptor -
                                 reinterpret_cast<const uint8_t *>(
                                     interfaceDescriptor));
}

bool controlTransfer(uint8_t rootPort, uint8_t stage,
                     const tusb_control_request_t *request) {
    if (stage != CONTROL_STAGE_SETUP) {
        return true;
    }
    if (request->bmRequestType_bit.type != TUSB_REQ_TYPE_CLASS ||
        request->bmRequestType_bit.recipient != TUSB_REQ_RCPT_INTERFACE ||
        static_cast<uint8_t>(request->wIndex) != s_interface) {
        return false;
    }

    switch (request->bRequest) {
        case 0x01: {
            const uint8_t slot = static_cast<uint8_t>(request->wValue);
            const uint8_t sequence = static_cast<uint8_t>(request->wValue >> 8);
            if (slot == 0 &&
                s_pendingRequest.load() == (kPendingFlag | sequence)) {
                s_abortedRequest.store(kPendingFlag | sequence);
            }
            return tud_control_status(rootPort, request);
        }
        case 0x02:
            return request->bmRequestType_bit.direction == TUSB_DIR_IN &&
                   tud_control_xfer(rootPort, request,
                                    const_cast<uint8_t *>(kClockAndDataRate),
                                    4);
        case 0x03:
            return request->bmRequestType_bit.direction == TUSB_DIR_IN &&
                   tud_control_xfer(rootPort, request,
                                    const_cast<uint8_t *>(kClockAndDataRate +
                                                          4),
                                    4);
        default:
            return false;
    }
}

bool endpointTransfer(uint8_t rootPort, uint8_t endpoint,
                      xfer_result_t result, uint32_t transferredBytes) {
    if (endpoint == s_inEndpoint) {
        xSemaphoreGive(s_transmitAvailable);
        return true;
    }
    if (endpoint != s_outEndpoint) {
        return false;
    }

    if (result != XFER_RESULT_SUCCESS ||
        transferredBytes > sizeof(s_outPacket) ||
        transferredBytes > sizeof(s_receivedMessage) - s_receivedLength) {
        s_receivedLength = 0;
        s_expectedLength = 0;
        armOutEndpoint();
        return true;
    }

    std::memcpy(s_receivedMessage + s_receivedLength, s_outPacket,
                transferredBytes);
    s_receivedLength += transferredBytes;
    if (s_expectedLength == 0 && s_receivedLength >= kHeaderSize) {
        const uint32_t bodyLength = readLittleEndian32(s_receivedMessage + 1);
        if (bodyLength <= kMaximumMessageLength - kHeaderSize) {
            s_expectedLength = kHeaderSize + bodyLength;
        } else {
            sendSlotFailure(s_receivedMessage[5], s_receivedMessage[6],
                            kBadLength);
            std::memset(s_receivedMessage, 0, s_receivedLength);
            s_receivedLength = 0;
        }
    }

    if (s_expectedLength != 0 && s_receivedLength >= s_expectedLength) {
        if (s_receivedLength == s_expectedLength) {
            processMessage(s_receivedMessage, s_receivedLength);
        }
        std::memset(s_receivedMessage, 0, s_receivedLength);
        s_receivedLength = 0;
        s_expectedLength = 0;
    }

    // A short packet ends a transfer. If the message it ended is still
    // incomplete, host and reader disagree about its length, and waiting for
    // the rest would glue the next message onto this one for good.
    if (s_receivedLength != 0 && transferredBytes < kEndpointSize) {
        if (s_receivedLength >= kHeaderSize) {
            sendSlotFailure(s_receivedMessage[5], s_receivedMessage[6],
                            kBadLength);
        }
        std::memset(s_receivedMessage, 0, s_receivedLength);
        s_receivedLength = 0;
        s_expectedLength = 0;
    }
    armOutEndpoint();
    return true;
}

void initDriver() {}
bool deinitDriver() { return true; }

const usbd_class_driver_t kCcidDriver = {
    .name = "CCID",
    .init = initDriver,
    .deinit = deinitDriver,
    .reset = resetDriver,
    .open = openDriver,
    .control_xfer_cb = controlTransfer,
    .xfer_cb = endpointTransfer,
    .xfer_isr = nullptr,
    .sof = nullptr,
};

}  // namespace

esp_err_t installCcidDevice() {
    s_requestQueue = xQueueCreate(1, sizeof(uint8_t));
    s_transmitAvailable = xSemaphoreCreateBinary();
    if (s_requestQueue == nullptr || s_transmitAvailable == nullptr) {
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreGive(s_transmitAvailable);

    uint8_t mac[6];
    ESP_RETURN_ON_ERROR(esp_efuse_mac_get_default(mac), "CCID",
                        "Unable to read device identifier");
    std::snprintf(s_serialNumber, sizeof(s_serialNumber),
                  "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2],
                  mac[3], mac[4], mac[5]);

    tinyusb_config_t configuration = TINYUSB_DEFAULT_CONFIG();
    configuration.descriptor.device = &kDeviceDescriptor;
    configuration.descriptor.string = s_strings;
    configuration.descriptor.string_count =
        static_cast<int>(sizeof(s_strings) / sizeof(s_strings[0]));
    configuration.descriptor.full_speed_config = kConfigurationDescriptor;
    return tinyusb_driver_install(&configuration);
}

bool waitForCcidRequest(CcidRequest &request, uint32_t timeoutMilliseconds) {
    uint8_t notification = 0;
    if (s_requestQueue == nullptr ||
        xQueueReceive(s_requestQueue, &notification,
                      pdMS_TO_TICKS(timeoutMilliseconds)) != pdTRUE ||
        notification != 1) {
        return false;
    }
    portENTER_CRITICAL(&s_requestLock);
    request = s_requestBuffer;
    std::memset(s_requestBuffer.apdu, 0, s_requestBuffer.apduLength);
    s_requestBuffer.powerEpoch = 0;
    s_requestBuffer.apduLength = 0;
    portEXIT_CRITICAL(&s_requestLock);
    return true;
}

bool sendCcidResponse(const CcidRequest &request, const uint8_t *response,
                      size_t responseLength) {
    const uint16_t token = kPendingFlag | request.sequence;
    if (s_pendingRequest.load() != token || responseLength == 0 ||
        responseLength > CcidRequest::kMaximumApduLength) {
        return false;
    }
    if (!sendResponse(kReaderToPcDataBlock, request.slot, request.sequence,
                      kCommandSucceededActive, kNoError, 0, response,
                      responseLength, pdMS_TO_TICKS(250))) {
        return false;
    }
    s_pendingRequest.store(0);
    return true;
}

bool sendCcidTimeExtension(const CcidRequest &request, uint8_t multiplier) {
    const uint16_t token = kPendingFlag | request.sequence;
    return multiplier != 0 && s_pendingRequest.load() == token &&
           sendResponse(kReaderToPcDataBlock, request.slot, request.sequence,
                        kCommandTimeExtensionActive, multiplier, 0, nullptr, 0,
                        pdMS_TO_TICKS(50));
}

bool ccidRequestWasAborted(const CcidRequest &request) {
    return s_abortedRequest.load() == (kPendingFlag | request.sequence);
}

uint32_t ccidPowerEpoch() { return s_powerEpoch.load(); }
uint32_t ccidSecureRequests() { return s_secureRequests.load(); }

bool takeAutotypeArm(uint8_t &seconds, bool &toWake) {
    const uint16_t request = s_autotypeArm.exchange(0);
    seconds = static_cast<uint8_t>(request);
    toWake = (request & kToWakeFlag) != 0;
    return (request & kPendingFlag) != 0;
}

void publishAutotypeStatus(uint8_t secondsRemaining, uint32_t emissions,
                           bool watchesForFree) {
    s_autotypeSecondsRemaining.store(secondsRemaining);
    s_autotypeEmissions.store(
        static_cast<uint8_t>(std::min<uint32_t>(emissions, 0xFF)));
    s_autotypeStatus.store(static_cast<uint8_t>(
        kStatusWakes | (watchesForFree ? kStatusWatchesForFree : 0)));
}

bool hostAsleep() { return tud_suspended(); }

bool wakeHost() { return tud_suspended() && tud_remote_wakeup(); }

bool sendKeyboardReport(const uint8_t report[8]) {
    // The endpoint is polled every 10 ms, so the previous report has gone
    // well inside this unless the host has stopped listening.
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (tud_hid_n_ready(kKeyboardInstance)) {
            return tud_hid_n_report(kKeyboardInstance, 0, report, 8);
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return false;
}

}  // namespace deskid

extern "C" const uint8_t *tud_hid_descriptor_report_cb(uint8_t instance) {
    return instance == deskid::kKeyboardInstance
               ? deskid::kKeyboardReportDescriptor
               : deskid::kArmingReportDescriptor;
}

extern "C" uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t,
                                          hid_report_type_t type,
                                          uint8_t *buffer, uint16_t length) {
    if (instance != deskid::kArmingInstance ||
        type != HID_REPORT_TYPE_FEATURE ||
        length < deskid::kArmingReportSize) {
        return 0;
    }
    std::memset(buffer, 0, deskid::kArmingReportSize);
    buffer[0] = 0x01;
    buffer[1] = deskid::s_autotypeSecondsRemaining.load();
    buffer[2] = deskid::s_autotypeEmissions.load();
#if defined(DESKID_ALLOW_AUTOTYPE)
    buffer[3] = deskid::s_autotypeStatus.load();
#endif
    return deskid::kArmingReportSize;
}

extern "C" void tud_hid_set_report_cb(uint8_t instance, uint8_t,
                                      hid_report_type_t type,
                                      const uint8_t *buffer, uint16_t length) {
#if defined(DESKID_ALLOW_AUTOTYPE)
    // Anything else addressed to either interface, the keyboard's LED report
    // included, is ignored. The seconds are capped where they are used.
    if (instance == deskid::kArmingInstance &&
        type == HID_REPORT_TYPE_FEATURE && length >= 2 &&
        (buffer[0] == deskid::kArmAutotypeCommand ||
         buffer[0] == deskid::kArmToWakeCommand)) {
        deskid::s_autotypeArm.store(static_cast<uint16_t>(
            deskid::kPendingFlag |
            (buffer[0] == deskid::kArmToWakeCommand ? deskid::kToWakeFlag
                                                    : 0) |
            buffer[1]));
    }
#else
    (void)instance;
    (void)type;
    (void)buffer;
    (void)length;
#endif
}

extern "C" const usbd_class_driver_t *usbd_app_driver_get_cb(
    uint8_t *driverCount) {
    *driverCount = 1;
    return &deskid::kCcidDriver;
}