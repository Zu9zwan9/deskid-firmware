// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

#if defined(DESKID_PRODUCTION) && defined(DESKID_BRINGUP_NO_SENSOR)
#error "DESKID_BRINGUP_NO_SENSOR must never reach a production image"
#endif

// The signature nonce comes from a generator this file seeds, and the PSA API
// has no way to pass one in. TF-PSA-Crypto keeps mbedtls_ecdsa_sign and
// HMAC_DRBG behind this switch. It has to precede every mbedTLS header.
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

// Those headers lay their structures out by the mbedTLS configuration, and
// this file must read the one the library was built with. platformio.ini
// passes it. A build that loses it would compile, and corrupt its stack.
#if !defined(MBEDTLS_CONFIG_FILE) || !defined(TF_PSA_CRYPTO_USER_CONFIG_FILE)
#error "build_flags must pass ESP-IDF's mbedTLS configuration, see platformio.ini"
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "bootloader_random.h"
#include "ccid_device.h"
#include "deskid_core.h"
#include "driver/gpio.h"
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "driver/uart.h"
#include "esp_check.h"
#include "esp_efuse.h"
#include "esp_random.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
// With ESP-IDF's configuration mbedTLS includes <pthread.h>, and picolibc
// declares pthread_exit with __noreturn after the declarator. In C++ that is
// [[noreturn]] on a type, a warning this file's -Werror turns into an error.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#include "mbedtls/md.h"
#include "mbedtls/private/ecdsa.h"
#include "mbedtls/private/hmac_drbg.h"
#pragma GCC diagnostic pop
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "soc/rtc_cntl_reg.h"

namespace {

constexpr char kFirmwareVersion[] = "0.1.0";
#if defined(DESKID_PRODUCTION)
constexpr uint8_t kBuildVariant = 0;
#elif defined(DESKID_BRINGUP_NO_SENSOR)
constexpr uint8_t kBuildVariant = 2;
#else
constexpr uint8_t kBuildVariant = 1;
#endif
constexpr gpio_num_t kFingerprintReceivePin = GPIO_NUM_43;
constexpr gpio_num_t kFingerprintTransmitPin = GPIO_NUM_44;
constexpr gpio_num_t kFingerprintWakePin = GPIO_NUM_4;
// The level WAKEUP takes with a finger on the ring. Measured on this bench's
// R503 on 2026-11-13 at ten samples a second: driven high while the ring is
// empty, driven low for the whole of each touch. A sensor with the opposite
// sense builds with -DDESKID_WAKE_TOUCHED_LEVEL=1.
#ifndef DESKID_WAKE_TOUCHED_LEVEL
#define DESKID_WAKE_TOUCHED_LEVEL 0
#endif
constexpr bool kWakeTouchedLevel = DESKID_WAKE_TOUCHED_LEVEL != 0;
// The internal bias holds an unconnected pin at the resting level, so a
// missing wire reads as an empty ring and never as a finger.
constexpr gpio_pull_mode_t kWakeRestingPull =
    kWakeTouchedLevel ? GPIO_PULLDOWN_ONLY : GPIO_PULLUP_ONLY;
constexpr uart_port_t kFingerprintUart = UART_NUM_1;
constexpr uint32_t kFingerprintBaudRate = 57600;
constexpr uint16_t kFingerprintCapacity = 200;
constexpr uint32_t kAuthenticationTimeoutMilliseconds = 30000;
// Touch ID is never "off": the button is live before anything asks, and the
// asking is what happens afterwards. DeskID matches that by scanning the ring
// whenever it is otherwise idle and keeping the result for this long. macOS
// draws its own PIN field before it ever reaches the card, so without this the
// user types six meaningless digits at a dark ring and only then gets told to
// touch it. With it the touch can happen first — on arrival, while the digits
// are still being typed — and the login APDU is answered with no wait at all.
//
// The window is the whole security trade: long enough to cover an unhurried
// arrival, short enough that a touch left behind is not a standing invitation.
// It is single use, and only the two login instructions can spend it
// (deskid::EarlyTouch::maySpend).
//
// Measured at the lock screen on 2026-09-02: 15 s covered a deliberate touch,
// click, six digits and Return, and did not cover the same sequence done at a
// normal pace. So it is the request window — a touch is good for exactly as
// long as a request would have waited for one, which is one number to explain
// rather than two.
constexpr uint64_t kEarlyTouchValidMilliseconds =
    kAuthenticationTimeoutMilliseconds;
// Idle scan cadence. The scan runs off the R503's WAKEUP line and nothing
// else: that pin is a touch-sense output the sensor powers from about 5 uA,
// so watching it costs one GPIO read.
//
// The obvious fallback — GenImg over UART, the way fingerPresent() probes
// during an authentication — must not be used here. GenImg is a full image
// capture: it powers the imaging array and the sensor LED. Inside a 30 s
// authentication window that is what it is for; four times a second forever it
// browned the 3V3 rail out badly enough to power-cycle the board and leave the
// R503 unauthenticated (measured 2026-09-02: `reset reason 1 (power-on)`,
// `sensor 2 (error)`, ring stuck on the last LED command that got through).
//
// So an unsoldered blue wire means no idle scan, and DeskID behaves exactly as
// it did before: the ring breathes when a request arrives.
constexpr uint32_t kIdleScanMilliseconds = 40;
// When the wake line cannot be trusted, the host says when the ring matters —
// the screen locked, or a password field took focus — and the board watches it
// with GenImg for a bounded window. Bounded is the whole point: continuously
// is what browned the rail out, a minute at a time while someone is actually
// logging in is not.
constexpr uint32_t kArmedScanMilliseconds = 250;
// How long each keyboard report stands before the next: a press and a release
// per key, so a key takes twice this. A static password typed faster than
// about 40 ms a key loses characters at the macOS login window (reports from
// YubiKey users); tune it here if a board ever drops a digit.
constexpr uint32_t kAutotypeReportMilliseconds = 30;
// How long the digits wait once the host says a woken lock screen is lit.
// The host goes by the display state, which leads the PIN field, and macOS
// drops the first keys after a display wake (user reports on 15.2 and
// 15.3.1). Tune it here if a board ever loses a digit after a wake.
constexpr uint32_t kAutotypeLitMilliseconds = 400;
constexpr uint8_t kMaximumArmSeconds = 120;
// The R503's own default. Level 5 is the strictest of the five and was the
// first choice here, but it rejected an enrolled finger often enough to be
// unusable: every rejection also spends one of the five attempts before a
// lockout that survives unplugging, so a strict threshold does not fail
// gracefully, it fails shut. The false-accept risk it buys back is bounded
// by that same limiter and by the fact that an attacker must already hold
// the device.
constexpr uint8_t kFingerprintSecurityLevel = 3;
// How long a finger rests on the ring before its enrollment image is taken.
constexpr int64_t kEnrollSettleMilliseconds = 300;
// A held finger gets several captures before it has to lift, the way Touch ID
// keeps trying: partial contact and a smeared first image are the normal case,
// not an attack. A rejected *touch* counts once against the rate limiter,
// however many of its images were rejected: deskid::AttemptLedger enforces
// both that and this limit. Shared by the gated wait and the idle scan — a
// single-shot idle match rejects ordinary touches that the gated path would
// have accepted.
constexpr int kRetriesPerTouch = deskid::kVerdictsPerTouch;
constexpr uint32_t kFingerprintFailureThreshold = 5;
constexpr uint64_t kFingerprintBaseLockoutMilliseconds = 15000;
constexpr uint64_t kFingerprintMaximumLockoutMilliseconds = 900000;
constexpr char kStorageNamespace[] = "deskid";
constexpr char kCertificateKey[] = "piv_cert";
constexpr char kPrivateKeyKey[] = "piv_key";
constexpr char kKeyManagementKey[] = "piv_km";
constexpr char kSensorPasswordKey[] = "finger_pwd";
constexpr char kSensorReadyKey[] = "finger_ready";
constexpr char kFailureCountKey[] = "finger_fail";
constexpr char kLockoutCountKey[] = "finger_lock";

void secureZero(void *data, size_t length) {
    volatile uint8_t *cursor = static_cast<volatile uint8_t *>(data);
    while (length-- != 0) {
        *cursor++ = 0;
    }
}

uint64_t millisecondsSinceBoot() {
    return static_cast<uint64_t>(esp_timer_get_time() / 1000);
}

// No radio ever runs on this board, and ESP-IDF only documents the hardware
// RNG as truly random while Wi-Fi or Bluetooth is up or this SAR ADC noise
// source is switched on. It samples a reserved internal channel, not a pad, so
// it does not disturb GPIO4. It is held only across the operations whose
// output has to be unpredictable: seeding PSA's generator, the sensor
// password, key generation and signing.
class EntropySource {
public:
    EntropySource() { bootloader_random_enable(); }
    ~EntropySource() { bootloader_random_disable(); }
    EntropySource(const EntropySource &) = delete;
    EntropySource &operator=(const EntropySource &) = delete;
};

struct DerElement {
    uint8_t tag = 0;
    const uint8_t *value = nullptr;
    size_t length = 0;
};

bool readDerElement(deskid::Bytes encoded, size_t &offset,
                    DerElement &element) {
    if (offset + 2 > encoded.size) {
        return false;
    }
    element.tag = encoded.data[offset++];
    const uint8_t firstLength = encoded.data[offset++];
    if ((firstLength & 0x80) == 0) {
        element.length = firstLength;
    } else {
        const size_t byteCount = firstLength & 0x7F;
        if (byteCount == 0 || byteCount > 3 || byteCount > encoded.size - offset) {
            return false;
        }
        element.length = 0;
        for (size_t index = 0; index < byteCount; ++index) {
            element.length = (element.length << 8) | encoded.data[offset++];
        }
        if (element.length < 0x80) {
            return false;
        }
    }
    if (element.length > encoded.size - offset) {
        return false;
    }
    element.value = encoded.data + offset;
    offset += element.length;
    return true;
}

bool extractSec1Scalar(deskid::Bytes encoded, uint8_t scalar[32]) {
    size_t offset = 0;
    DerElement sequence;
    if (!readDerElement(encoded, offset, sequence) || sequence.tag != 0x30 ||
        offset != encoded.size) {
        return false;
    }

    deskid::Bytes contents{sequence.value, sequence.length};
    offset = 0;
    DerElement version;
    DerElement privateKey;
    return readDerElement(contents, offset, version) && version.tag == 0x02 &&
           readDerElement(contents, offset, privateKey) &&
           privateKey.tag == 0x04 && privateKey.length == 32 &&
           (std::memcpy(scalar, privateKey.value, 32), true);
}

bool extractPrivateScalar(deskid::Bytes encoded, uint8_t scalar[32]) {
    if (encoded.size == 32) {
        std::memcpy(scalar, encoded.data, 32);
        return true;
    }

    size_t offset = 0;
    DerElement sequence;
    if (!readDerElement(encoded, offset, sequence) || sequence.tag != 0x30 ||
        offset != encoded.size) {
        return false;
    }
    deskid::Bytes contents{sequence.value, sequence.length};
    offset = 0;
    DerElement version;
    DerElement next;
    if (!readDerElement(contents, offset, version) || version.tag != 0x02 ||
        !readDerElement(contents, offset, next)) {
        return false;
    }
    if (next.tag == 0x04 && next.length == 32) {
        std::memcpy(scalar, next.value, 32);
        return true;
    }
    if (next.tag != 0x30) {
        return false;
    }

    DerElement wrappedKey;
    if (!readDerElement(contents, offset, wrappedKey) ||
        wrappedKey.tag != 0x04) {
        return false;
    }
    return extractSec1Scalar({wrappedKey.value, wrappedKey.length}, scalar);
}

bool extractCertificatePublicKey(deskid::Bytes certificate,
                                 uint8_t publicKey[65]) {
    size_t offset = 0;
    DerElement certificateSequence;
    if (!readDerElement(certificate, offset, certificateSequence) ||
        certificateSequence.tag != 0x30 || offset != certificate.size) {
        return false;
    }

    deskid::Bytes certificateContents{certificateSequence.value,
                                      certificateSequence.length};
    offset = 0;
    DerElement tbsCertificate;
    if (!readDerElement(certificateContents, offset, tbsCertificate) ||
        tbsCertificate.tag != 0x30) {
        return false;
    }

    deskid::Bytes tbs{tbsCertificate.value, tbsCertificate.length};
    offset = 0;
    DerElement field;
    if (!readDerElement(tbs, offset, field)) {
        return false;
    }
    if (field.tag == 0xA0 && !readDerElement(tbs, offset, field)) {
        return false;
    }
    if (field.tag != 0x02) {
        return false;
    }
    for (size_t index = 0; index < 4; ++index) {
        if (!readDerElement(tbs, offset, field)) {
            return false;
        }
    }

    DerElement subjectPublicKeyInfo;
    if (!readDerElement(tbs, offset, subjectPublicKeyInfo) ||
        subjectPublicKeyInfo.tag != 0x30) {
        return false;
    }
    deskid::Bytes spki{subjectPublicKeyInfo.value,
                       subjectPublicKeyInfo.length};
    offset = 0;
    DerElement algorithm;
    DerElement bitString;
    if (!readDerElement(spki, offset, algorithm) || algorithm.tag != 0x30 ||
        !readDerElement(spki, offset, bitString) || bitString.tag != 0x03 ||
        offset != spki.size || bitString.length != 66 ||
        bitString.value[0] != 0 || bitString.value[1] != 0x04) {
        return false;
    }
    constexpr uint8_t p256Algorithm[] = {
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
        0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    };
    if (algorithm.length != sizeof(p256Algorithm) ||
        std::memcmp(algorithm.value, p256Algorithm,
                    sizeof(p256Algorithm)) != 0) {
        return false;
    }
    std::memcpy(publicKey, bitString.value + 1, 65);
    return true;
}

size_t encodeDerInteger(const uint8_t value[32], uint8_t *destination,
                        size_t capacity) {
    size_t first = 0;
    while (first < 31 && value[first] == 0) {
        ++first;
    }
    const bool leadingZero = (value[first] & 0x80) != 0;
    const size_t valueLength = 32 - first + (leadingZero ? 1 : 0);
    if (capacity < valueLength + 2) {
        return 0;
    }
    destination[0] = 0x02;
    destination[1] = static_cast<uint8_t>(valueLength);
    size_t offset = 2;
    if (leadingZero) {
        destination[offset++] = 0;
    }
    std::memcpy(destination + offset, value + first, 32 - first);
    return valueLength + 2;
}

// ECDSA over P-256 with a hedged nonce. An HMAC_DRBG seeded with fresh
// randomness, the private scalar and the digest picks it;
// deskid::hedgedNonceSeed has the layout and the reasons. PSA's randomized
// ECDSA rests every nonce on the random generator alone, and one biased or
// repeated nonce gives the key away. PSA's deterministic ECDSA repeats the
// nonce for a repeated digest, which is what a fault attack on a token needs.
bool signHedged(const uint8_t scalar[32], const uint8_t digest[32],
                const uint8_t randomness[32], uint8_t rawSignature[64]) {
    uint8_t seed[deskid::kHedgedNonceSeedSize];
    deskid::hedgedNonceSeed(randomness, scalar, digest, seed);

    mbedtls_ecp_group group;
    mbedtls_mpi d;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_hmac_drbg_context generator;
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_hmac_drbg_init(&generator);

    // The nonce is the generator's first output. mbedtls_ecdsa_sign draws its
    // blinding values from the same generator afterwards.
    const bool succeeded =
        mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_mpi_read_binary(&d, scalar, 32) == 0 &&
        mbedtls_hmac_drbg_seed_buf(
            &generator, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), seed,
            sizeof(seed)) == 0 &&
        mbedtls_ecdsa_sign(&group, &r, &s, &d, digest, 32,
                           mbedtls_hmac_drbg_random, &generator) == 0 &&
        mbedtls_mpi_write_binary(&r, rawSignature, 32) == 0 &&
        mbedtls_mpi_write_binary(&s, rawSignature + 32, 32) == 0;

    mbedtls_hmac_drbg_free(&generator);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&group);
    secureZero(seed, sizeof(seed));
    return succeeded;
}

// Known answer for signHedged: the key and the SHA-256("sample") digest of
// RFC 6979 A.2.5, with Z = 00 01 .. 1F. tools/hedged_ecdsa_reference.py
// derives the signature and first proves itself against the RFC's own vector.
// The draft the layout comes from publishes no vectors.
bool signingSelfTest() {
    static constexpr uint8_t kScalar[32] = {
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21,
        0x57, 0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8,
        0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
    };
    static constexpr uint8_t kDigest[32] = {
        0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1,
        0xD6, 0x94, 0xF4, 0x1F, 0xC7, 0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9,
        0x89, 0x15, 0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF,
    };
    static constexpr uint8_t kSignature[64] = {
        0x5D, 0x5E, 0x79, 0x71, 0xBD, 0xE5, 0x28, 0x33, 0xBD, 0x53, 0x97,
        0x91, 0x4C, 0x61, 0x6E, 0x64, 0x17, 0x5E, 0x47, 0xC0, 0xD8, 0x32,
        0x99, 0x25, 0xD1, 0x6A, 0x3D, 0xC7, 0x2B, 0xF7, 0xC2, 0x0F,
        0x7A, 0xEC, 0x33, 0x60, 0x16, 0x49, 0xF5, 0xA9, 0x5A, 0x19, 0x3A,
        0x0F, 0x9D, 0xEB, 0x88, 0xF6, 0x5A, 0x18, 0x2A, 0x40, 0x07, 0x5B,
        0xBD, 0x1E, 0x9B, 0x45, 0x1B, 0x0E, 0xE1, 0x96, 0xD9, 0x7E,
    };
    uint8_t randomness[32];
    for (size_t index = 0; index < sizeof(randomness); ++index) {
        randomness[index] = static_cast<uint8_t>(index);
    }
    uint8_t signature[64];
    return signHedged(kScalar, kDigest, randomness, signature) &&
           std::memcmp(signature, kSignature, sizeof(signature)) == 0;
}

class StoredPivCredential final : public deskid::PivCredential {
public:
    ~StoredPivCredential() override {
        if (keyId_ != PSA_KEY_ID_NULL) {
            psa_destroy_key(keyId_);
        }
        if (pendingKeyId_ != PSA_KEY_ID_NULL) {
            psa_destroy_key(pendingKeyId_);
        }
        if (kmKeyId_ != PSA_KEY_ID_NULL) {
            psa_destroy_key(kmKeyId_);
        }
        if (kmPendingKeyId_ != PSA_KEY_ID_NULL) {
            psa_destroy_key(kmPendingKeyId_);
        }
        secureZero(privateKeyDer_.data(), privateKeyDer_.size());
    }

    esp_err_t initialize() {
        const EntropySource entropy;
        if (psa_crypto_init() != PSA_SUCCESS) {
            return ESP_FAIL;
        }
        // A failure leaves the board up, so the status object can say why it
        // will not sign.
        signingSelfTestPassed_ = signingSelfTest();

        nvs_handle_t handle;
        ESP_RETURN_ON_ERROR(nvs_open(kStorageNamespace, NVS_READWRITE, &handle),
                            "IDENTITY", "Unable to open credential storage");
        const esp_err_t result = loadSensorPassword(handle);
        if (result == ESP_OK) {
            loadCredential(handle);
            loadKeyManagement(handle);
        }
        nvs_close(handle);
        return result;
    }

    bool signingSelfTestPassed() const { return signingSelfTestPassed_; }

    deskid::Bytes certificateDer(deskid::Slot slot) const override {
        if (slot == deskid::Slot::keyManagement) {
            return {kmBlob_.data() + kScalarLength, kmCertificateLength_};
        }
        return {certificate_.data(), certificateLength_};
    }

    deskid::Bytes deviceIdentifier() const override {
        if (certificateLength_ == 0) {
            return {nullptr, 0};
        }
        return {identifier_.data(), identifier_.size()};
    }

    bool signP256Sha256(deskid::Bytes digest, uint8_t *signature,
                        size_t capacity, size_t &signatureLength) override {
        signatureLength = 0;
        if (digest.data == nullptr || digest.size != 32 ||
            signature == nullptr || capacity < 72 ||
            keyId_ == PSA_KEY_ID_NULL || !signingSelfTestPassed_) {
            return false;
        }

        uint8_t rawSignature[64];
        uint8_t scalar[32];
        uint8_t randomness[32];
        size_t scalarLength = 0;
        const EntropySource entropy;
        const bool succeeded =
            psa_generate_random(randomness, sizeof(randomness)) ==
                PSA_SUCCESS &&
            psa_export_key(keyId_, scalar, sizeof(scalar), &scalarLength) ==
                PSA_SUCCESS &&
            scalarLength == sizeof(scalar) &&
            signHedged(scalar, digest.data, randomness, rawSignature);
        secureZero(scalar, sizeof(scalar));
        secureZero(randomness, sizeof(randomness));
        if (!succeeded) {
            secureZero(rawSignature, sizeof(rawSignature));
            return false;
        }

        signature[0] = 0x30;
        const size_t rLength = encodeDerInteger(rawSignature, signature + 2,
                                                capacity - 2);
        const size_t sLength =
            encodeDerInteger(rawSignature + 32, signature + 2 + rLength,
                             capacity - 2 - rLength);
        secureZero(rawSignature, sizeof(rawSignature));
        if (rLength == 0 || sLength == 0 || rLength + sLength > 0x7F) {
            return false;
        }
        signature[1] = static_cast<uint8_t>(rLength + sLength);
        signatureLength = 2 + rLength + sLength;
        return true;
    }

    bool generateKeyP256(deskid::Slot slot, uint8_t *publicKey,
                         size_t capacity, size_t &publicKeyLength) override {
        const bool keyManagement = slot == deskid::Slot::keyManagement;
        psa_key_id_t &pending = keyManagement ? kmPendingKeyId_ : pendingKeyId_;
        publicKeyLength = 0;
        if (publicKey == nullptr || capacity < 65) {
            return false;
        }
        if (pending != PSA_KEY_ID_NULL) {
            psa_destroy_key(pending);
            pending = PSA_KEY_ID_NULL;
        }

        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(
            &attributes,
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, 256);
        // The signing key is export only, like the one loadCredential
        // imports: signHedged is the one signer. The key management key
        // agrees keys through PSA, so it alone gets an algorithm.
        psa_set_key_usage_flags(
            &attributes,
            keyManagement ? PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT
                          : PSA_KEY_USAGE_EXPORT);
        if (keyManagement) {
            psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
        }
        const EntropySource entropy;
        const psa_status_t generateStatus =
            psa_generate_key(&attributes, &pending);
        psa_reset_key_attributes(&attributes);
        if (generateStatus != PSA_SUCCESS) {
            pending = PSA_KEY_ID_NULL;
            return false;
        }

        size_t exportedLength = 0;
        if (psa_export_public_key(pending, publicKey, capacity,
                                  &exportedLength) != PSA_SUCCESS ||
            exportedLength != 65) {
            psa_destroy_key(pending);
            pending = PSA_KEY_ID_NULL;
            return false;
        }
        publicKeyLength = exportedLength;
        return true;
    }

    // A generated key stays volatile until the matching certificate arrives.
    // Persisting it earlier would leave a key that no stored certificate
    // matches, and initialize() refuses to boot that pair.
    bool storeCertificate(deskid::Slot slot,
                          deskid::Bytes certificateDer) override {
        if (slot == deskid::Slot::keyManagement) {
            return storeKeyManagementCertificate(certificateDer);
        }
        if (certificateDer.data == nullptr || certificateDer.size == 0 ||
            certificateDer.size > certificate_.size()) {
            return false;
        }
        uint8_t certificatePublicKey[65];
        if (!extractCertificatePublicKey(certificateDer,
                                         certificatePublicKey)) {
            return false;
        }
        const bool adoptsPendingKey =
            publicKeyMatches(pendingKeyId_, certificatePublicKey);
        if (!adoptsPendingKey &&
            !publicKeyMatches(keyId_, certificatePublicKey)) {
            return false;
        }

        uint8_t scalar[32]{};
        size_t scalarLength = 0;
        if (adoptsPendingKey &&
            (psa_export_key(pendingKeyId_, scalar, sizeof(scalar),
                            &scalarLength) != PSA_SUCCESS ||
             scalarLength != sizeof(scalar))) {
            secureZero(scalar, sizeof(scalar));
            return false;
        }

        nvs_handle_t handle;
        esp_err_t result = nvs_open(kStorageNamespace, NVS_READWRITE, &handle);
        if (result == ESP_OK) {
            result = nvs_set_blob(handle, kCertificateKey, certificateDer.data,
                                  certificateDer.size);
            if (result == ESP_OK && adoptsPendingKey) {
                result =
                    nvs_set_blob(handle, kPrivateKeyKey, scalar, scalarLength);
            }
            if (result == ESP_OK) {
                result = nvs_commit(handle);
            }
            nvs_close(handle);
        }
        secureZero(scalar, sizeof(scalar));
        if (result != ESP_OK) {
            return false;
        }

        if (adoptsPendingKey) {
            if (keyId_ != PSA_KEY_ID_NULL) {
                psa_destroy_key(keyId_);
            }
            keyId_ = pendingKeyId_;
            pendingKeyId_ = PSA_KEY_ID_NULL;
        }
        std::memcpy(certificate_.data(), certificateDer.data,
                    certificateDer.size);
        certificateLength_ = certificateDer.size;
        return refreshIdentifier() == ESP_OK;
    }

    // ECDH with the slot 9D key. PSA rejects a peer point that is not on the
    // curve before it computes anything.
    bool agreeP256(deskid::Bytes peerPoint, uint8_t *secret, size_t capacity,
                   size_t &secretLength) override {
        secretLength = 0;
        if (peerPoint.data == nullptr || peerPoint.size != 65 ||
            secret == nullptr || capacity < kScalarLength ||
            kmKeyId_ == PSA_KEY_ID_NULL) {
            return false;
        }
        size_t length = 0;
        const EntropySource entropy;
        if (psa_raw_key_agreement(PSA_ALG_ECDH, kmKeyId_, peerPoint.data,
                                  peerPoint.size, secret, capacity,
                                  &length) != PSA_SUCCESS ||
            length != kScalarLength) {
            secureZero(secret, capacity);
            return false;
        }
        secretLength = length;
        return true;
    }

    uint32_t sensorPassword() const { return sensorPassword_; }
    bool sensorProvisioned() const { return sensorProvisioned_; }

    esp_err_t markSensorProvisioned() {
        if (sensorProvisioned_) {
            return ESP_OK;
        }
        nvs_handle_t handle;
        ESP_RETURN_ON_ERROR(
            nvs_open(kStorageNamespace, NVS_READWRITE, &handle), "IDENTITY",
            "Unable to open credential state");
        esp_err_t result = nvs_set_u8(handle, kSensorReadyKey, 1);
        if (result == ESP_OK) {
            result = nvs_commit(handle);
        }
        nvs_close(handle);
        if (result == ESP_OK) {
            sensorProvisioned_ = true;
        }
        return result;
    }

private:
    // A unit is manufactured by flashing firmware alone, so the sensor password
    // is created here on first boot and never leaves the board. Erasing NVS
    // therefore strands the sensor at the password it was already given.
    esp_err_t loadSensorPassword(nvs_handle_t handle) {
        esp_err_t result =
            nvs_get_u32(handle, kSensorPasswordKey, &sensorPassword_);
        if (result == ESP_ERR_NVS_NOT_FOUND ||
            (result == ESP_OK && sensorPassword_ == 0)) {
            while (sensorPassword_ == 0) {
                esp_fill_random(&sensorPassword_, sizeof(sensorPassword_));
            }
            result = nvs_set_u32(handle, kSensorPasswordKey, sensorPassword_);
            if (result == ESP_OK) {
                result = nvs_commit(handle);
            }
        }
        ESP_RETURN_ON_ERROR(result, "IDENTITY",
                            "Unable to establish the sensor password");

        uint8_t ready = 0;
        result = nvs_get_u8(handle, kSensorReadyKey, &ready);
        sensorProvisioned_ = result == ESP_OK && ready == 1;
        return result == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : result;
    }

    // A factory board carries no identity, and a corrupt one must not brick the
    // unit: both still enumerate, so provisioning over USB can create a new
    // identity and the status object reports which case it is.
    void loadCredential(nvs_handle_t handle) {
        size_t certificateLength = certificate_.size();
        if (nvs_get_blob(handle, kCertificateKey, certificate_.data(),
                         &certificateLength) != ESP_OK ||
            certificateLength == 0) {
            return;
        }

        uint8_t scalar[32];
        size_t keyLength = privateKeyDer_.size();
        const bool loaded =
            nvs_get_blob(handle, kPrivateKeyKey, privateKeyDer_.data(),
                         &keyLength) == ESP_OK &&
            keyLength != 0 &&
            extractPrivateScalar({privateKeyDer_.data(), keyLength}, scalar);
        secureZero(privateKeyDer_.data(), privateKeyDer_.size());
        if (!loaded) {
            secureZero(scalar, sizeof(scalar));
            return;
        }

        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(
            &attributes,
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, 256);
        // PSA holds the key and hands it to signHedged. It gets no signing
        // algorithm, so nothing can sign with a PSA-chosen nonce by mistake.
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
        const psa_status_t importStatus =
            psa_import_key(&attributes, scalar, sizeof(scalar), &keyId_);
        psa_reset_key_attributes(&attributes);
        secureZero(scalar, sizeof(scalar));
        if (importStatus != PSA_SUCCESS) {
            keyId_ = PSA_KEY_ID_NULL;
            return;
        }

        uint8_t certificatePublicKey[65];
        certificateLength_ = certificateLength;
        if (!extractCertificatePublicKey(
                {certificate_.data(), certificateLength_},
                certificatePublicKey) ||
            !publicKeyMatches(keyId_, certificatePublicKey) ||
            refreshIdentifier() != ESP_OK) {
            psa_destroy_key(keyId_);
            keyId_ = PSA_KEY_ID_NULL;
            certificateLength_ = 0;
        }
    }

    // Slot 9D is one NVS blob, scalar then certificate, so a pulled plug
    // cannot leave a key beside a certificate that does not match it. The
    // scalar is in kmBlob_ only while the blob is being read or written.
    void loadKeyManagement(nvs_handle_t handle) {
        if (kmKeyId_ != PSA_KEY_ID_NULL) {
            psa_destroy_key(kmKeyId_);
            kmKeyId_ = PSA_KEY_ID_NULL;
        }
        kmCertificateLength_ = 0;

        size_t length = kmBlob_.size();
        psa_status_t importStatus = PSA_ERROR_DOES_NOT_EXIST;
        if (nvs_get_blob(handle, kKeyManagementKey, kmBlob_.data(),
                         &length) == ESP_OK &&
            length > kScalarLength) {
            psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
            psa_set_key_type(
                &attributes,
                PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            psa_set_key_bits(&attributes, 256);
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
            psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
            importStatus = psa_import_key(&attributes, kmBlob_.data(),
                                          kScalarLength, &kmKeyId_);
            psa_reset_key_attributes(&attributes);
        }
        secureZero(kmBlob_.data(), kScalarLength);
        if (importStatus != PSA_SUCCESS) {
            kmKeyId_ = PSA_KEY_ID_NULL;
            return;
        }

        uint8_t certificatePublicKey[65];
        if (!extractCertificatePublicKey(
                {kmBlob_.data() + kScalarLength, length - kScalarLength},
                certificatePublicKey) ||
            !publicKeyMatches(kmKeyId_, certificatePublicKey)) {
            psa_destroy_key(kmKeyId_);
            kmKeyId_ = PSA_KEY_ID_NULL;
            return;
        }
        kmCertificateLength_ = length - kScalarLength;
    }

    // Accepts a certificate for the key generated a moment ago, or a new
    // certificate for the key already installed.
    bool storeKeyManagementCertificate(deskid::Bytes certificateDer) {
        if (certificateDer.data == nullptr || certificateDer.size == 0 ||
            certificateDer.size > kmBlob_.size() - kScalarLength) {
            return false;
        }
        uint8_t certificatePublicKey[65];
        if (!extractCertificatePublicKey(certificateDer,
                                         certificatePublicKey)) {
            return false;
        }
        const bool adoptsPendingKey =
            publicKeyMatches(kmPendingKeyId_, certificatePublicKey);
        if (!adoptsPendingKey &&
            !publicKeyMatches(kmKeyId_, certificatePublicKey)) {
            return false;
        }

        nvs_handle_t handle;
        if (nvs_open(kStorageNamespace, NVS_READWRITE, &handle) != ESP_OK) {
            return false;
        }
        // The scalar comes from the pending key, or from the blob the
        // installed key was loaded from: that key cannot be exported.
        bool haveScalar = false;
        if (adoptsPendingKey) {
            size_t scalarLength = 0;
            haveScalar = psa_export_key(kmPendingKeyId_, kmBlob_.data(),
                                        kScalarLength,
                                        &scalarLength) == PSA_SUCCESS &&
                         scalarLength == kScalarLength;
        } else {
            size_t storedLength = kmBlob_.size();
            haveScalar = nvs_get_blob(handle, kKeyManagementKey,
                                      kmBlob_.data(),
                                      &storedLength) == ESP_OK &&
                         storedLength > kScalarLength;
        }
        bool stored = false;
        if (haveScalar) {
            std::memcpy(kmBlob_.data() + kScalarLength, certificateDer.data,
                        certificateDer.size);
            stored = nvs_set_blob(handle, kKeyManagementKey, kmBlob_.data(),
                                  kScalarLength + certificateDer.size) ==
                         ESP_OK &&
                     nvs_commit(handle) == ESP_OK;
        }
        if (stored && adoptsPendingKey) {
            psa_destroy_key(kmPendingKeyId_);
            kmPendingKeyId_ = PSA_KEY_ID_NULL;
        }
        // Whatever happened, memory is brought back in line with flash. The
        // key comes back without the right to be exported.
        loadKeyManagement(handle);
        nvs_close(handle);
        return stored && kmCertificateLength_ == certificateDer.size;
    }

    bool publicKeyMatches(psa_key_id_t keyId,
                          const uint8_t expected[65]) const {
        if (keyId == PSA_KEY_ID_NULL) {
            return false;
        }
        uint8_t exported[65];
        size_t exportedLength = 0;
        return psa_export_public_key(keyId, exported, sizeof(exported),
                                     &exportedLength) == PSA_SUCCESS &&
               exportedLength == sizeof(exported) &&
               std::memcmp(expected, exported, sizeof(exported)) == 0;
    }

    esp_err_t refreshIdentifier() {
        uint8_t certificateHash[32];
        size_t hashLength = 0;
        if (psa_hash_compute(PSA_ALG_SHA_256, certificate_.data(),
                             certificateLength_, certificateHash,
                             sizeof(certificateHash),
                             &hashLength) != PSA_SUCCESS ||
            hashLength != sizeof(certificateHash)) {
            secureZero(certificateHash, sizeof(certificateHash));
            return ESP_FAIL;
        }
        std::memcpy(identifier_.data(), certificateHash, identifier_.size());
        secureZero(certificateHash, sizeof(certificateHash));
        return ESP_OK;
    }

    std::array<uint8_t, 1800> certificate_{};
    std::array<uint8_t, 512> privateKeyDer_{};
    std::array<uint8_t, 16> identifier_{};
    size_t certificateLength_ = 0;
    psa_key_id_t keyId_ = PSA_KEY_ID_NULL;
    psa_key_id_t pendingKeyId_ = PSA_KEY_ID_NULL;
    // Slot 9D: the scalar's 32 bytes, zero except during a read or write of
    // the blob, then the certificate.
    static constexpr size_t kScalarLength = 32;
    std::array<uint8_t, kScalarLength + 1800> kmBlob_{};
    size_t kmCertificateLength_ = 0;
    psa_key_id_t kmKeyId_ = PSA_KEY_ID_NULL;
    psa_key_id_t kmPendingKeyId_ = PSA_KEY_ID_NULL;
    uint32_t sensorPassword_ = 0;
    bool sensorProvisioned_ = false;
    bool signingSelfTestPassed_ = false;
};

class R503Sensor {
public:
    enum class MatchResult {
        noFinger,
        matched,
        notMatched,
        sensorError,
    };

    esp_err_t initialize(uint32_t password, bool allowInitialPasswordChange) {
        uart_config_t uartConfiguration{};
        uartConfiguration.baud_rate = kFingerprintBaudRate;
        uartConfiguration.data_bits = UART_DATA_8_BITS;
        uartConfiguration.parity = UART_PARITY_DISABLE;
        uartConfiguration.stop_bits = UART_STOP_BITS_1;
        uartConfiguration.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
        uartConfiguration.source_clk = UART_SCLK_DEFAULT;
        ESP_RETURN_ON_ERROR(uart_param_config(kFingerprintUart,
                                              &uartConfiguration),
                            "R503", "Unable to configure UART");
        ESP_RETURN_ON_ERROR(
            uart_driver_install(kFingerprintUart, 512, 0, 0, nullptr, 0),
            "R503", "Unable to install UART driver");

        gpio_config_t wakeConfiguration{};
        wakeConfiguration.pin_bit_mask = 1ULL << kFingerprintWakePin;
        wakeConfiguration.mode = GPIO_MODE_INPUT;
        wakeConfiguration.pull_down_en = kWakeTouchedLevel
                                             ? GPIO_PULLDOWN_ENABLE
                                             : GPIO_PULLDOWN_DISABLE;
        wakeConfiguration.pull_up_en =
            kWakeTouchedLevel ? GPIO_PULLUP_DISABLE : GPIO_PULLUP_ENABLE;
        wakeConfiguration.intr_type = GPIO_INTR_DISABLE;
        ESP_RETURN_ON_ERROR(gpio_config(&wakeConfiguration), "R503",
                            "Unable to configure wake pin");

        // The Super Mini's front silkscreen misprints RX next to both UART
        // pads, so a miswired pair is easy and silent. Probe the documented
        // orientation first, then the swap, and keep the one the sensor
        // answers on. Weak drive limits the contention current while the
        // wrong orientation has our transmitter facing the sensor's.
        gpio_set_drive_capability(kFingerprintTransmitPin, GPIO_DRIVE_CAP_0);
        gpio_set_drive_capability(kFingerprintReceivePin, GPIO_DRIVE_CAP_0);
        for (const bool swapped : {false, true}) {
            const gpio_num_t transmitPin =
                swapped ? kFingerprintReceivePin : kFingerprintTransmitPin;
            const gpio_num_t receivePin =
                swapped ? kFingerprintTransmitPin : kFingerprintReceivePin;
            ESP_RETURN_ON_ERROR(
                uart_set_pin(kFingerprintUart, transmitPin, receivePin,
                             UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE),
                "R503", "Unable to assign UART pins");
            vTaskDelay(pdMS_TO_TICKS(200));
            uart_flush_input(kFingerprintUart);
            if (!authenticate(password, allowInitialPasswordChange)) {
                continue;
            }
            if (!enforceSecurityLevel(password, kFingerprintSecurityLevel)) {
                return ESP_ERR_INVALID_STATE;
            }
            refreshTemplateCount();
            password_ = password;
            setLed(0x04, 0x02, 0);
            return ESP_OK;
        }
        return ESP_ERR_INVALID_RESPONSE;
    }

    bool wakeLineHigh() const {
        return gpio_get_level(kFingerprintWakePin) == 1;
    }

    // The wake line is believed only after it has been seen at both levels:
    // see deskid::WakeLine. An earlier note here recorded the line as high
    // "in every state including firm ring contact". That was the resting
    // level read between touches, and the firmware took it for a finger.
    void observeWakeLine() { wakeLine_.observe(wakeLineHigh()); }

    bool wakeLineUsable() const { return wakeLine_.usable(); }

    bool wakeLineTouched() const { return wakeLine_.touched(wakeLineHigh()); }

    // What GPIO4 does under each internal bias, as `pullUp << 1 | pullDown`.
    // A pin nothing is driving follows the bias and reads 0b10; a pin being
    // driven reads the same both ways. So:
    //
    //   0b10  floating  — the blue wire is not connected, or the R503's
    //                     WAKEUP is open-drain and idle
    //   0b11  driven high
    //   0b00  driven low
    //
    // Sample it untouched and again with a finger on the ring and the wiring
    // question answers itself, including which sense this R503 uses. This
    // bench's sensor reads 0b11 empty and 0b00 touched.
    uint8_t wakeLineBias() const {
        gpio_set_pull_mode(kFingerprintWakePin, GPIO_PULLUP_ONLY);
        vTaskDelay(pdMS_TO_TICKS(2));
        const int pulledUp = gpio_get_level(kFingerprintWakePin);
        gpio_set_pull_mode(kFingerprintWakePin, GPIO_PULLDOWN_ONLY);
        vTaskDelay(pdMS_TO_TICKS(2));
        const int pulledDown = gpio_get_level(kFingerprintWakePin);
        gpio_set_pull_mode(kFingerprintWakePin, kWakeRestingPull);
        return static_cast<uint8_t>(pulledUp << 1 | pulledDown);
    }

    // A brownout, a nudged wire or a glitch on the 3V3 rail restarts the R503
    // mid-session, and every command after that fails because the password has
    // to be presented again. Nothing recovered from that: the ring stayed lit
    // on whatever LED command last got through and the board needed unplugging.
    // Re-authenticating costs one UART round trip every two seconds while the
    // sensor is unhappy, and nothing at all when it is not.
    bool recover() {
        if (state_ != 2 || password_ == 0) {
            return state_ == 1;
        }
        uart_flush_input(kFingerprintUart);
        if (!verifyPassword(password_)) {
            return false;
        }
        refreshTemplateCount();
        // Whatever the ring showed before this start is not known.
        ring_ = Ring::touched;
        turnLedOff();
        return true;
    }

    // WAKEUP is a shortcut, not a requirement: GenImg answers 0x02 when the
    // ring is untouched, so an unwired or broken wake line costs a UART round
    // trip rather than the sensor. A line read with the wrong sense is the
    // same kind of broken: it reports a finger on an empty ring, so the gate
    // never sees the ring released and refuses a second touch until it times
    // out.
    //
    // Every look at the ring is also a look at the wake line. The line is
    // believed once it has been seen at both levels, and the idle loop alone
    // used to do the looking. A first touch that answered a request never
    // counted, so after power-on the board could not watch a dark lock screen
    // until a touch had been spent on nothing (bench, 2026-11-13 20:34).
    bool fingerPresent() {
        observeWakeLine();
        if (wakeLineTouched()) {
            return true;
        }
        uint8_t confirmation = 0xFF;
        size_t responseLength = 0;
        return command(0x01, nullptr, 0, confirmation, nullptr, 0,
                       responseLength) &&
               confirmation == 0x00;
    }

    bool authenticate(uint32_t password, bool allowInitialPasswordChange) {
        return verifyPassword(password) ||
               (allowInitialPasswordChange && password != 0 &&
                verifyPassword(0) && changePassword(password) &&
                verifyPassword(password));
    }

    MatchResult captureAndMatch(uint16_t &fingerId, uint16_t &confidence,
                                deskid::AttemptLedger &ledger) {
        fingerId = 0;
        confidence = 0;

        uint8_t confirmation = 0xFF;
        size_t responseLength = 0;
        if (!command(0x01, nullptr, 0, confirmation, nullptr, 0,
                     responseLength)) {
            return MatchResult::sensorError;
        }
        if (confirmation == 0x02) {
            return MatchResult::noFinger;
        }
        if (confirmation != 0x00) {
            return MatchResult::sensorError;
        }

        constexpr uint8_t imageBuffer[] = {0x01};
        if (!command(0x02, imageBuffer, sizeof(imageBuffer), confirmation,
                     nullptr, 0, responseLength) || confirmation != 0x00) {
            return MatchResult::sensorError;
        }

        // Search is the verdict, so the attempt is charged and written down
        // before it is sent: see deskid::AttemptLedger. Nothing above this
        // line tells an attacker anything, and nothing below it is free. The
        // charge is one a touch: later images of the same touch ride on it.
        if (!ledger.chargeTouch(millisecondsSinceBoot())) {
            return MatchResult::sensorError;
        }

        const uint8_t searchParameters[] = {
            0x01,
            0x00,
            0x00,
            static_cast<uint8_t>(kFingerprintCapacity >> 8),
            static_cast<uint8_t>(kFingerprintCapacity),
        };
        uint8_t response[4];
        if (!command(0x04, searchParameters, sizeof(searchParameters),
                     confirmation, response, sizeof(response),
                     responseLength)) {
            return MatchResult::sensorError;
        }
        if (confirmation == 0x09) {
            return MatchResult::notMatched;
        }
        if (confirmation != 0x00 || responseLength != sizeof(response)) {
            return MatchResult::sensorError;
        }
        fingerId = static_cast<uint16_t>(response[0] << 8 | response[1]);
        confidence = static_cast<uint16_t>(response[2] << 8 | response[3]);
        return MatchResult::matched;
    }

    // R503 Empty (0x0D). The only way back from a template the sensor no
    // longer recognises, since a bad enrollment cannot be selectively deleted
    // without knowing which slot went wrong.
    bool empty() {
        uint8_t confirmation = 0xFF;
        size_t responseLength = 0;
        if (!command(0x0D, nullptr, 0, confirmation, nullptr, 0,
                     responseLength) ||
            confirmation != 0x00) {
            return false;
        }
        templateCount_ = 0;
        templateCountKnown_ = true;
        enrollRingSeenEmpty_ = false;
        enrollFingerDownAtUs_ = 0;
        return true;
    }

    // One image is one template. Two touches that had to agree with each
    // other could not record how a finger lands when nobody is thinking
    // about it, and that is the placement worth having: on 2026-11-13 pairs
    // of natural touches failed to merge for minutes. A finger is a set of
    // such templates, the way a phone records one from many placements.
    uint8_t enrollStep() {
        const bool present = fingerPresent();
        // The first image has to come from a touch that began for it. The
        // finger that authorized this enrollment, or the placement stored a
        // moment ago, is still on the ring when the step runs, and capturing
        // it again would add nothing.
        if (!enrollRingSeenEmpty_) {
            // The last look, stored or failed, finishes before the next.
            if (ringBusy()) {
                return present ? 4 : 0;
            }
            if (present) {
                show(Ring::enrollLift);
                return 4;
            }
            enrollRingSeenEmpty_ = true;
            show(Ring::enrollPlace);
        }
        if (!present) {
            enrollFingerDownAtUs_ = 0;
            return 0;
        }
        // An image taken as the finger lands is smeared, and with one image a
        // template there is no second to make up for it.
        const int64_t now = esp_timer_get_time();
        if (enrollFingerDownAtUs_ == 0) {
            enrollFingerDownAtUs_ = now;
        }
        if (now - enrollFingerDownAtUs_ < kEnrollSettleMilliseconds * 1000LL) {
            return 0;
        }
        uint8_t confirmation = captureInto(0x01);
        if (confirmation == 0x02) {
            return 0;
        }
        if (confirmation != 0x00) {
            return abortEnrollment(Ring::adjust);
        }
        // DeskID never deletes a template, so the library has no gaps and the
        // count is also the next free page. A count the sensor never reported
        // would aim this at page 0 and overwrite whoever is enrolled there.
        if (!templateCountKnown_) {
            return abortEnrollment(Ring::failure);
        }
        // RegModel wants two character files and gets the same image twice.
        // ponytail: if this unit refuses that, the character file in buffer
        // 1 is stored as it is; the two have one format on this sensor
        // family. Which path ran is not reported.
        const uint8_t second[] = {0x02};
        size_t responseLength = 0;
        if (command(0x02, second, sizeof(second), confirmation, nullptr, 0,
                    responseLength) &&
            confirmation == 0x00) {
            command(0x05, nullptr, 0, confirmation, nullptr, 0,
                    responseLength);
        }
        const uint8_t store[] = {
            0x01,
            static_cast<uint8_t>(templateCount_ >> 8),
            static_cast<uint8_t>(templateCount_),
        };
        if (!command(0x06, store, sizeof(store), confirmation, nullptr, 0,
                     responseLength) ||
            confirmation != 0x00) {
            return abortEnrollment(Ring::failure);
        }
        enrollRingSeenEmpty_ = false;
        enrollFingerDownAtUs_ = 0;
        refreshTemplateCount();
        show(Ring::enrollStored);
        return 3;
    }

    // What the ring is saying. One look a state, so a glance at the sensor
    // answers "what does it want from me": see kRingLooks.
    enum class Ring : uint8_t {
        off,
        waiting,       // a host asked for a touch
        touched,       // contact, image being read
        success,
        failure,       // the touch was rejected
        adjust,        // no usable image: lift and lie flatter
        lockedOut,
        enrollPlace,   // place the finger to enroll
        enrollLift,    // lift the finger
        enrollStored,
    };

    void show(Ring ring) {
        const RingLook &look = kRingLooks[static_cast<size_t>(ring)];
        if (ring == ring_ && look.milliseconds == 0) {
            return;  // already showing it; spare the UART
        }
        ring_ = ring;
        ringOffAtUs_ = look.milliseconds == 0
                           ? 0
                           : esp_timer_get_time() + look.milliseconds * 1000LL;
        setLed(look.control, look.color, 0);
    }
    // Ends a timed look. The sensor's own flash count would do it too, but
    // its speed scale is undocumented and a look cut short by the next
    // command is how the red flash went unseen.
    void serviceRing() {
        if (ringBusy() && esp_timer_get_time() >= ringOffAtUs_) {
            show(Ring::off);
        }
    }
    bool ringBusy() const { return ringOffAtUs_ != 0; }
    bool showing(Ring ring) const { return ring_ == ring; }

    void showWaiting() { show(Ring::waiting); }
    // The ring answers contact, not the match that follows it. Reading an
    // image takes a few hundred milliseconds and a dark sensor during them
    // reads as a sensor that missed the finger, so the light goes solid the
    // moment skin lands.
    void showTouched() { show(Ring::touched); }
    void showSuccess() { show(Ring::success); }
    void showFailure() { show(Ring::failure); }
    void showAdjust() { show(Ring::adjust); }
    void showLockedOut() { show(Ring::lockedOut); }
    void turnLedOff() { show(Ring::off); }

    uint8_t state() const { return state_; }
    uint8_t lastConfirmation() const { return lastConfirmation_; }
    uint16_t templateCount() const { return templateCount_; }
    bool templateCountKnown() const { return templateCountKnown_; }

    // The R503 stores the level itself, so a reboot puts the compiled default
    // back: this is a live measurement aid, not a setting.
    bool enforceSecurityLevel(uint32_t password, uint8_t requiredLevel) {
        uint8_t confirmation = 0xFF;
        uint8_t parameters[16];
        size_t responseLength = 0;
        if (!command(0x0F, nullptr, 0, confirmation, parameters,
                     sizeof(parameters), responseLength) ||
            confirmation != 0x00 || responseLength != sizeof(parameters)) {
            return false;
        }
        const uint16_t currentLevel =
            static_cast<uint16_t>(parameters[6] << 8 | parameters[7]);
        if (currentLevel == requiredLevel) {
            return true;
        }
        const uint8_t setting[] = {0x05, requiredLevel};
        if (!command(0x0E, setting, sizeof(setting), confirmation, nullptr, 0,
                     responseLength) ||
            confirmation != 0x00 ||
            !command(0x3D, nullptr, 0, confirmation, nullptr, 0,
                     responseLength) ||
            confirmation != 0x00) {
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
        if (!verifyPassword(password) ||
            !command(0x0F, nullptr, 0, confirmation, parameters,
                     sizeof(parameters), responseLength) ||
            confirmation != 0x00 || responseLength != sizeof(parameters)) {
            return false;
        }
        return static_cast<uint16_t>(parameters[6] << 8 | parameters[7]) ==
               requiredLevel;
    }

private:
    bool passwordCommand(uint8_t instruction, uint32_t password) {
        uint8_t parameters[] = {
            static_cast<uint8_t>(password >> 24),
            static_cast<uint8_t>(password >> 16),
            static_cast<uint8_t>(password >> 8),
            static_cast<uint8_t>(password),
        };
        uint8_t confirmation = 0xFF;
        size_t responseLength = 0;
        const bool succeeded =
            command(instruction, parameters, sizeof(parameters), confirmation,
                    nullptr, 0, responseLength) &&
            confirmation == 0x00;
        secureZero(parameters, sizeof(parameters));
        return succeeded;
    }

    bool verifyPassword(uint32_t password) {
        return passwordCommand(0x13, password);
    }

    bool changePassword(uint32_t password) {
        return passwordCommand(0x12, password);
    }

    bool readExact(uint8_t *destination, size_t length,
                   uint32_t timeoutMilliseconds) {
        const int64_t deadline = esp_timer_get_time() +
                                 timeoutMilliseconds * 1000LL;
        size_t offset = 0;
        while (offset < length) {
            const int64_t remainingMicroseconds =
                deadline - esp_timer_get_time();
            if (remainingMicroseconds <= 0) {
                return false;
            }
            const TickType_t timeout = std::max<TickType_t>(
                1, pdMS_TO_TICKS((remainingMicroseconds + 999) / 1000));
            const int received = uart_read_bytes(
                kFingerprintUart, destination + offset, length - offset,
                timeout);
            if (received <= 0) {
                return false;
            }
            offset += static_cast<size_t>(received);
        }
        return true;
    }

    bool command(uint8_t instruction, const uint8_t *parameters,
                 size_t parameterLength, uint8_t &confirmation,
                 uint8_t *response, size_t responseCapacity,
                 size_t &responseLength) {
        responseLength = 0;
        if (parameterLength > 32 ||
            (parameterLength != 0 && parameters == nullptr)) {
            return false;
        }
        state_ = 2;

        uint8_t packet[44];
        const uint16_t packetLength =
            static_cast<uint16_t>(parameterLength + 3);
        constexpr uint8_t prefix[] = {0xEF, 0x01, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0x01};
        std::memcpy(packet, prefix, sizeof(prefix));
        packet[7] = static_cast<uint8_t>(packetLength >> 8);
        packet[8] = static_cast<uint8_t>(packetLength);
        packet[9] = instruction;
        if (parameterLength != 0) {
            std::memcpy(packet + 10, parameters, parameterLength);
        }
        uint16_t checksum = 0x01 + packet[7] + packet[8] + instruction;
        for (size_t index = 0; index < parameterLength; ++index) {
            checksum += parameters[index];
        }
        packet[10 + parameterLength] = static_cast<uint8_t>(checksum >> 8);
        packet[11 + parameterLength] = static_cast<uint8_t>(checksum);

        uart_flush_input(kFingerprintUart);
        const size_t totalLength = 12 + parameterLength;
        const bool transmitted =
            uart_write_bytes(kFingerprintUart, packet, totalLength) ==
                static_cast<int>(totalLength) &&
            uart_wait_tx_done(kFingerprintUart, pdMS_TO_TICKS(100)) == ESP_OK;
        secureZero(packet, sizeof(packet));
        if (!transmitted) {
            return false;
        }

        uint8_t header[9];
        if (!readExact(header, sizeof(header), 500) || header[0] != 0xEF ||
            header[1] != 0x01 || header[2] != 0xFF || header[3] != 0xFF ||
            header[4] != 0xFF || header[5] != 0xFF || header[6] != 0x07) {
            return false;
        }
        const uint16_t acknowledgementLength =
            static_cast<uint16_t>(header[7] << 8 | header[8]);
        if (acknowledgementLength < 3 || acknowledgementLength > 35) {
            return false;
        }
        uint8_t payload[35];
        if (!readExact(payload, acknowledgementLength, 500)) {
            return false;
        }

        uint16_t expectedChecksum = 0x07 + header[7] + header[8];
        for (size_t index = 0; index < acknowledgementLength - 2; ++index) {
            expectedChecksum += payload[index];
        }
        const uint16_t receivedChecksum = static_cast<uint16_t>(
            payload[acknowledgementLength - 2] << 8 |
            payload[acknowledgementLength - 1]);
        if (expectedChecksum != receivedChecksum) {
            return false;
        }

        confirmation = payload[0];
        if (confirmation != 0x00) {
            lastConfirmation_ = confirmation;
        }
        state_ = 1;
        responseLength = acknowledgementLength - 3;
        if (responseLength > responseCapacity ||
            (responseLength != 0 && response == nullptr)) {
            return false;
        }
        if (responseLength != 0) {
            std::memcpy(response, payload + 1, responseLength);
        }
        return true;
    }

    uint8_t captureInto(uint8_t buffer) {
        uint8_t confirmation = 0xFF;
        size_t responseLength = 0;
        if (!command(0x01, nullptr, 0, confirmation, nullptr, 0,
                     responseLength)) {
            return 0xFF;
        }
        if (confirmation != 0x00) {
            return confirmation;
        }
        const uint8_t parameters[] = {buffer};
        if (!command(0x02, parameters, sizeof(parameters), confirmation,
                     nullptr, 0, responseLength)) {
            return 0xFF;
        }
        return confirmation;
    }

    uint8_t abortEnrollment(Ring look) {
        enrollRingSeenEmpty_ = false;
        enrollFingerDownAtUs_ = 0;
        show(look);
        return 0xFF;
    }

    void refreshTemplateCount() {
        uint8_t confirmation = 0xFF;
        uint8_t response[2];
        size_t responseLength = 0;
        if (command(0x1D, nullptr, 0, confirmation, response,
                    sizeof(response), responseLength) &&
            confirmation == 0x00 && responseLength == sizeof(response)) {
            templateCount_ =
                static_cast<uint16_t>(response[0] << 8 | response[1]);
            templateCountKnown_ = true;
        }
    }

    // R503 AuraLedConfig. Control: 1 breathing, 2 flashing, 3 on, 4 off.
    // Colour: 1 red, 2 blue, 3 purple on every unit; 4 green, 5 yellow,
    // 6 cyan and 7 white on units with a green LED. The numbers read as a
    // red, blue, green mask, so a unit without green is asked again for the
    // same look less its green: white becomes purple and yellow red. Green
    // alone would leave nothing, and becomes blue.
    struct RingLook {
        uint8_t control;
        uint8_t color;
        uint16_t milliseconds;  // 0: stays until the next look
    };
    static constexpr RingLook kRingLooks[] = {
        {0x04, 0x02, 0},     // off
        {0x01, 0x07, 0},     // waiting: white, breathing
        {0x03, 0x02, 0},     // touched: blue
        {0x03, 0x04, 700},   // success: green
        {0x02, 0x01, 1300},  // failure: red, flashing
        {0x02, 0x05, 1300},  // adjust: yellow, flashing
        {0x01, 0x01, 0},     // lockedOut: red, breathing
        {0x01, 0x03, 0},     // enrollPlace: purple, breathing
        {0x03, 0x03, 0},     // enrollLift: purple
        {0x02, 0x04, 1000},  // enrollStored: green, flashing
    };

    void setLed(uint8_t control, uint8_t color, uint8_t times) {
        uint8_t parameters[] = {control, 0x40, color, times};
        uint8_t confirmation = 0xFF;
        size_t responseLength = 0;
        const bool sent = command(0x35, parameters, sizeof(parameters),
                                  confirmation, nullptr, 0, responseLength);
        if (sent && confirmation != 0x00 && (color & 0x04) != 0) {
            parameters[2] = (color & 0x03) != 0 ? (color & 0x03) : 0x02;
            command(0x35, parameters, sizeof(parameters), confirmation,
                    nullptr, 0, responseLength);
        }
    }

    uint8_t state_ = 0;
    deskid::WakeLine wakeLine_{kWakeTouchedLevel};
    uint32_t password_ = 0;
    uint8_t lastConfirmation_ = 0;
    uint16_t templateCount_ = 0;
    bool templateCountKnown_ = false;
    bool enrollRingSeenEmpty_ = false;
    int64_t enrollFingerDownAtUs_ = 0;
    // Unknown at power-up, so anything but off: the first off is then sent.
    Ring ring_ = Ring::touched;
    int64_t ringOffAtUs_ = 0;
};

// Finger-on to match-confirmed for the last successful authentication, the
// number the product is judged by. Read back through status tag 0x0D.
uint32_t g_lastMatchMilliseconds = 0;
// Why the last presence gate ended, and which instruction asked for it.
// Tags 0x0E / 0x0F in the status object. 1 matched, 2 timed out, 3 aborted
// by the host, 4 card re-powered, 5 rate-limiter lockout, 6 sensor absent.
uint8_t g_lastGateOutcome = 0;
uint8_t g_lastGateInstruction = 0;
// A match that happened before any host asked for one. Reported through status
// tags 0x11 and 0x12; the policy it enforces is tested in test/test_piv.
deskid::EarlyTouch g_earlyTouch(kEarlyTouchValidMilliseconds);
// Whether a host has asked for the PIN digits to be typed after the next
// match. The policy is deskid::Autotype and is tested in test/test_piv.
deskid::Autotype g_autotype;

// Types the digits and Return. Blocking on purpose: whatever the host sends
// meanwhile, a press is followed by its release, because a key left down
// repeats until something else is typed. Unused in the sensorless bring-up
// build, where no touch ever matches.
[[maybe_unused]] void typeDummyPin() {
    uint8_t report[8];
    for (size_t index = 0; index < deskid::Autotype::kReportCount; ++index) {
        deskid::Autotype::report(index, report);
        if (!deskid::sendKeyboardReport(report)) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(kAutotypeReportMilliseconds));
    }
    // However the loop ended, nothing may stay pressed.
    std::memset(report, 0, sizeof(report));
    deskid::sendKeyboardReport(report);
}

// Wakes the Mac: its display, and the Mac itself when the bus is suspended.
[[maybe_unused]] void wakeMac() {
    // A sleeping Mac takes no key reports. It is woken the way a key press
    // on a sleeping keyboard wakes it, and the tap that follows is the user
    // activity that lights the display.
    if (deskid::wakeHost()) {
        for (int wait = 0; wait < 100 && deskid::hostAsleep(); ++wait) {
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
    uint8_t report[8];
    deskid::Autotype::wakeReport(true, report);
    if (deskid::sendKeyboardReport(report)) {
        vTaskDelay(pdMS_TO_TICKS(kAutotypeReportMilliseconds));
    }
    deskid::Autotype::wakeReport(false, report);
    deskid::sendKeyboardReport(report);
}

// Owned by the idle scanner below, but also cleared by the gated path, which
// drives the same ring and leaves the same finger resting on it.
// Until when the host has asked the board to watch its own sensor.
uint64_t g_ringArmedUntilMs = 0;

bool ringArmed() { return millisecondsSinceBoot() < g_ringArmedUntilMs; }

bool g_idleWaitForRemoval = false;
bool g_idleRingLit = false;
bool g_idleLockoutShown = false;
// When the finger currently on the ring first landed. A capture that comes
// back "image too messy" is retried, and timing from the retry rather than
// from contact would quietly flatter the one number the product is judged by.
int64_t g_idleTouchStartedAtUs = 0;
int g_idleRetriesThisTouch = 0;

class BoardDiagnostics final : public deskid::DeviceDiagnostics {
public:
    BoardDiagnostics(const StoredPivCredential &credential, R503Sensor &sensor,
                     const deskid::RateLimiter &limiter)
        : credential_(credential), sensor_(sensor), limiter_(limiter) {}

    deskid::DeviceStatus status() const override {
        const uint64_t now = millisecondsSinceBoot();
        deskid::DeviceStatus value;
        value.firmwareVersion = kFirmwareVersion;
        value.buildVariant = kBuildVariant;
        value.uptimeSeconds = static_cast<uint32_t>(now / 1000);
        value.resetReason = static_cast<uint8_t>(esp_reset_reason());
        value.freeHeapBytes = esp_get_free_heap_size();
        value.sensorState = sensor_.state();
        value.lastSensorConfirmation = sensor_.lastConfirmation();
        value.credentialPresent =
            credential_.certificateDer(deskid::Slot::authentication).size != 0;
        value.consecutiveFailures = static_cast<uint8_t>(
            std::min<uint32_t>(limiter_.consecutiveFailures(), 0xFF));
        value.lockoutSecondsRemaining = static_cast<uint32_t>(
            (limiter_.lockoutMillisecondsRemaining(now) + 999) / 1000);
        value.enrolledTemplates = sensor_.templateCount();
        value.templateCountKnown = sensor_.templateCountKnown();
        value.wakeLineHigh = sensor_.wakeLineHigh();
        value.lastMatchMilliseconds = g_lastMatchMilliseconds;
        value.lastGateOutcome = g_lastGateOutcome;
        value.lastGateInstruction = g_lastGateInstruction;
        value.secureRequests = deskid::ccidSecureRequests();
        value.earlyTouchGates = g_earlyTouch.gates();
        value.wakeLineBias = sensor_.wakeLineBias();
        value.signingSelfTestPassed = credential_.signingSelfTestPassed();
        value.ringArmedSecondsRemaining = static_cast<uint8_t>(
            ringArmed() ? std::min<uint64_t>(
                              255, (g_ringArmedUntilMs - now + 999) / 1000)
                        : 0);
        value.touchValidSecondsRemaining = static_cast<uint8_t>(
            std::min<uint64_t>(
                255, (g_earlyTouch.millisecondsRemaining(now) + 999) / 1000));
        return value;
    }

    uint64_t uptimeMilliseconds() const override {
        return millisecondsSinceBoot();
    }

    bool enrollStep(uint8_t &stage) override {
#if defined(DESKID_BRINGUP_NO_SENSOR)
        (void)stage;
        return false;
#else
        stage = sensor_.enrollStep();
        return true;
#endif
    }

    bool armRing(uint8_t seconds) override {
        const uint8_t capped = std::min(seconds, kMaximumArmSeconds);
        g_ringArmedUntilMs =
            millisecondsSinceBoot() + static_cast<uint64_t>(capped) * 1000;
        return true;
    }

    bool forgetFingerprints() override {
#if defined(DESKID_BRINGUP_NO_SENSOR)
        return false;
#else
        return sensor_.empty();
#endif
    }

    bool enterDownloadMode() override {
#if defined(DESKID_ALLOW_DOWNLOAD_MODE)
        downloadModePending_ = true;
        return true;
#else
        return false;
#endif
    }

    void rebootIfRequested() {
#if defined(DESKID_ALLOW_DOWNLOAD_MODE)
        if (!downloadModePending_) {
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_restart();
#endif
    }

private:
    const StoredPivCredential &credential_;
    R503Sensor &sensor_;
    const deskid::RateLimiter &limiter_;
    bool downloadModePending_ = false;
};

// The lockout has to outlive a power cycle, or unplugging the device would be
// the cheapest way to clear a run of failed matches.
class NvsLimiterStore final : public deskid::LimiterStore {
public:
    void load(deskid::RateLimiter &limiter) {
        nvs_handle_t handle;
        if (nvs_open(kStorageNamespace, NVS_READONLY, &handle) != ESP_OK) {
            return;
        }
        nvs_get_u32(handle, kFailureCountKey, &savedFailures_);
        nvs_get_u32(handle, kLockoutCountKey, &savedLockouts_);
        nvs_close(handle);
        limiter.restore(savedFailures_, savedLockouts_,
                        millisecondsSinceBoot());
    }

    // Two entries cannot be written as one, so the order is chosen for the
    // plug being pulled between them. The lockout count goes first: a torn
    // write then leaves a new lockout beside a stale, higher failure count,
    // which is stricter than either state and never more lenient.
    bool save(uint32_t consecutiveFailures, uint32_t lockoutCount) override {
        if (consecutiveFailures == savedFailures_ &&
            lockoutCount == savedLockouts_) {
            return true;
        }
        nvs_handle_t handle;
        if (nvs_open(kStorageNamespace, NVS_READWRITE, &handle) != ESP_OK) {
            return false;
        }
        const bool written =
            nvs_set_u32(handle, kLockoutCountKey, lockoutCount) == ESP_OK &&
            nvs_commit(handle) == ESP_OK &&
            nvs_set_u32(handle, kFailureCountKey, consecutiveFailures) ==
                ESP_OK &&
            nvs_commit(handle) == ESP_OK;
        nvs_close(handle);
        if (written) {
            savedFailures_ = consecutiveFailures;
            savedLockouts_ = lockoutCount;
        }
        return written;
    }

private:
    uint32_t savedFailures_ = 0;
    uint32_t savedLockouts_ = 0;
};

// One poll of the idle ring. The sensor is live between host requests, not
// only while one is waiting, so a finger that lands on arrival is matched
// there and then and the result held for kEarlyTouchValidMilliseconds. That
// is what removes the dead time the product is actually judged by: macOS
// draws its own PIN field before it ever reaches the card, and without this
// the sensor stays dark until those digits have been typed.
//
// At most one capture per call, so a request arriving mid-match waits for one
// match and not for a loop.
void scanForEarlyTouch(R503Sensor &sensor, deskid::RateLimiter &limiter,
                       deskid::AttemptLedger &ledger) {
#if defined(DESKID_BRINGUP_NO_SENSOR)
    // No sensor, so no touch to be early with; the gate approves everything
    // anyway and pretending otherwise would hide that in the status object.
    (void)sensor;
    (void)limiter;
    (void)ledger;
#else
    // sensorState 1 is "the R503 answered". An unwired or dead sensor must
    // not turn this into a UART probe every 40 ms forever.
    if (sensor.state() != 1 || sensor.templateCount() == 0) {
        return;
    }

    // Two ways to know a finger is there, and the cheap one is only used when
    // the hardware has proved it works: see observeWakeLine(). Otherwise the
    // host has to say when it is worth spending an image capture on.
    const bool present = sensor.wakeLineUsable() ? sensor.wakeLineTouched()
                                                 : sensor.fingerPresent();
    if (limiter.locked(millisecondsSinceBoot())) {
        // A locked-out ring that stays dark reads as a dead board. It says
        // so to whoever touches it, and asks the sensor nothing.
        if (present != g_idleLockoutShown) {
            g_idleLockoutShown = present;
            if (present) {
                sensor.showLockedOut();
            } else {
                sensor.turnLedOff();
            }
        }
        return;
    }
    if (g_idleLockoutShown) {
        // The lockout ran out under a resting finger.
        g_idleLockoutShown = false;
        sensor.turnLedOff();
    }
    if (!present) {
        ledger.touchEnded();
        g_idleWaitForRemoval = false;
        g_idleTouchStartedAtUs = 0;
        g_idleRetriesThisTouch = 0;
        if (g_idleRingLit) {
            sensor.turnLedOff();
            g_idleRingLit = false;
        }
        return;
    }
    // One rejected match per touch, so a wallet resting on the ring costs the
    // rate limiter one attempt rather than a lockout. Holding a match already
    // means there is nothing to gain from another, unless a host has since
    // armed the board to type. Typing takes a touch that lands after the
    // arming: a touch left behind earlier must not unlock a screen that
    // locked after it.
    if (g_idleWaitForRemoval ||
        (g_earlyTouch.held(millisecondsSinceBoot()) &&
         g_autotype.secondsRemaining(millisecondsSinceBoot()) == 0)) {
        return;
    }

    if (g_idleTouchStartedAtUs == 0) {
        g_idleTouchStartedAtUs = esp_timer_get_time();
    }
    if (!g_idleRingLit) {
        sensor.showTouched();
        g_idleRingLit = true;
    }
    uint16_t fingerId = 0;
    uint16_t confidence = 0;
    switch (sensor.captureAndMatch(fingerId, confidence, ledger)) {
        case R503Sensor::MatchResult::matched:
            g_lastMatchMilliseconds = static_cast<uint32_t>(
                (esp_timer_get_time() - g_idleTouchStartedAtUs) / 1000);
            g_idleRetriesThisTouch = 0;
            ledger.matched();
            g_earlyTouch.record(millisecondsSinceBoot());
            sensor.showSuccess();
            // The touch is recorded first, so the login instruction the typed
            // Return sets off finds it.
            if (g_autotype.take(millisecondsSinceBoot())) {
                if (g_autotype.wakes()) {
                    // The digits follow when the host says the screen is lit.
                    wakeMac();
                } else {
                    typeDummyPin();
                }
            } else if (deskid::hostAsleep()) {
                // No helper runs on a Mac that is asleep, so nothing armed
                // the board. A match still wakes it, and is held for the
                // arming that follows once the lock screen is lit.
                wakeMac();
                g_autotype.wokeHost(millisecondsSinceBoot());
            }
            // The look ends itself; a lifting finger must not cut it short.
            g_idleRingLit = false;
            g_idleWaitForRemoval = true;
            return;
        case R503Sensor::MatchResult::notMatched:
            // Charged and written down before the touch's first verdict.
            if (!limiter.locked(millisecondsSinceBoot()) &&
                ++g_idleRetriesThisTouch < kRetriesPerTouch) {
                return;  // still the same finger; try the next image
            }
            sensor.showFailure();
            g_idleRingLit = false;
            g_idleWaitForRemoval = true;
            return;
        case R503Sensor::MatchResult::sensorError:
        case R503Sensor::MatchResult::noFinger:
            // Half a finger, or it lifted between the wake line and the
            // capture. Nothing was rejected, so nothing is spent and the ring
            // stays lit while the next poll tries again — blinking it off and
            // on per attempt would read as a sensor that keeps losing the
            // finger. When the tries run out the ring asks for a better
            // placement, which is a different thing from a rejection.
            if (limiter.locked(millisecondsSinceBoot())) {
                sensor.showFailure();
            } else if (++g_idleRetriesThisTouch >= kRetriesPerTouch * 2) {
                sensor.showAdjust();
            } else {
                return;
            }
            g_idleRingLit = false;
            g_idleWaitForRemoval = true;
            return;
    }
#endif
}

bool authorizeFingerprint(R503Sensor &sensor, deskid::RateLimiter &limiter,
                          deskid::AttemptLedger &ledger,
                          const deskid::CcidRequest &request,
                          uint32_t powerEpoch) {
#if defined(DESKID_BRINGUP_NO_SENSOR)
    // ponytail: bench bring-up with no R503 attached approves every request,
    // so there is no user presence at all. Drop the flag once the sensor is
    // wired to restore the real match gate.
    (void)sensor;
    (void)limiter;
    (void)ledger;
    (void)request;
    (void)powerEpoch;
    return true;
#else
    g_lastGateInstruction = request.apduLength > 1 ? request.apdu[1] : 0;
    // Only a submitted PIN field makes macOS ask for this, so digits typed
    // for a match that woke the Mac have landed.
    g_autotype.hostActed();
    g_lastGateOutcome = 2;
    // A touch that already happened answers the login instructions with no
    // wait at all. It is spent here whether or not what follows succeeds, so
    // one touch is one operation and it can never be replayed.
    if (g_earlyTouch.spend(g_lastGateInstruction, millisecondsSinceBoot())) {
        g_lastGateOutcome = 7;
        return true;
    }
    if (limiter.locked(millisecondsSinceBoot())) {
        g_lastGateOutcome = 5;
        return false;
    }
    // Anything the host asks for now supersedes the idle scan, which shares
    // the ring and may have left a finger resting on it.
    g_idleWaitForRemoval = false;
    g_idleRingLit = false;
    sensor.showWaiting();
    const int64_t deadline = esp_timer_get_time() +
                             kAuthenticationTimeoutMilliseconds * 1000LL;
    int64_t nextTimeExtension = esp_timer_get_time();
    int64_t fingerSeenAt = 0;
    bool waitForFingerRemoval = false;
    int retriesThisTouch = 0;

    while (esp_timer_get_time() < deadline) {
        sensor.serviceRing();
        if (deskid::ccidRequestWasAborted(request) ||
            deskid::ccidPowerEpoch() != powerEpoch) {
            g_lastGateOutcome = deskid::ccidRequestWasAborted(request) ? 3 : 4;
            sensor.turnLedOff();
            g_idleWaitForRemoval = true;
            return false;
        }
        const int64_t now = esp_timer_get_time();
        if (now >= nextTimeExtension) {
            deskid::sendCcidTimeExtension(request);
            nextTimeExtension = now + 750000;
        }

        if (!sensor.fingerPresent()) {
            ledger.touchEnded();
            fingerSeenAt = 0;
            retriesThisTouch = 0;
            waitForFingerRemoval = false;
            // Breathing again, once a rejection has had its flash.
            if (!sensor.ringBusy()) {
                sensor.showWaiting();
            }
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        if (fingerSeenAt == 0) {
            fingerSeenAt = esp_timer_get_time();
            // Contact is answered before the match it starts. A capture takes
            // a few hundred milliseconds and a ring that keeps breathing
            // through them reads as one that missed the finger.
            sensor.showTouched();
        }
        if (waitForFingerRemoval) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        deskid::sendCcidTimeExtension(request);
        uint16_t fingerId = 0;
        uint16_t confidence = 0;
        switch (sensor.captureAndMatch(fingerId, confidence, ledger)) {
            case R503Sensor::MatchResult::matched:
                g_lastMatchMilliseconds = static_cast<uint32_t>(
                    (esp_timer_get_time() - fingerSeenAt) / 1000);
                g_lastGateOutcome = 1;
                ledger.matched();
                // The look ends itself, so the host has its answer at once.
                sensor.showSuccess();
                g_idleWaitForRemoval = true;
                return true;
            case R503Sensor::MatchResult::notMatched:
                // Charged and written down before the touch's first verdict.
                if (limiter.locked(millisecondsSinceBoot())) {
                    sensor.showFailure();
                    g_idleWaitForRemoval = true;
                    return false;
                }
                if (++retriesThisTouch < kRetriesPerTouch) {
                    vTaskDelay(pdMS_TO_TICKS(120));
                    break;
                }
                sensor.showFailure();
                waitForFingerRemoval = true;
                break;
            case R503Sensor::MatchResult::sensorError:
                // The last permitted attempt is charged before its verdict.
                // If the sensor then gave none, the lockout stands.
                if (limiter.locked(millisecondsSinceBoot())) {
                    sensor.showFailure();
                    g_idleWaitForRemoval = true;
                    return false;
                }
                // Usually "image too messy" from Img2Tz: the finger moved or
                // only half landed. Try again while it is still there.
                if (++retriesThisTouch < kRetriesPerTouch * 2) {
                    vTaskDelay(pdMS_TO_TICKS(80));
                    break;
                }
                sensor.showAdjust();
                waitForFingerRemoval = true;
                break;
            case R503Sensor::MatchResult::noFinger:
                break;
        }
    }
    sensor.turnLedOff();
    g_idleWaitForRemoval = true;
    return false;
#endif
}

}  // namespace

// The board's WS2812 hangs on GPIO48 and nothing drove that pin, so the LED
// showed whatever its floating data line picked up. One all-zero frame
// switches it off, and the pin is then held at the idle level so no noise
// reaches it. The LED is decoration: a failure here is ignored.
static void darkenBoardLed() {
    constexpr gpio_num_t kPin = GPIO_NUM_48;
    rmt_tx_channel_config_t channelConfig = {};
    channelConfig.gpio_num = kPin;
    channelConfig.clk_src = RMT_CLK_SRC_DEFAULT;
    channelConfig.resolution_hz = 10000000;  // 0.1 us a tick
    channelConfig.mem_block_symbols = 64;
    channelConfig.trans_queue_depth = 1;

    // WS2812B bit times: a zero is 0.3 us high and 0.9 us low, a one the
    // reverse.
    rmt_bytes_encoder_config_t encoderConfig = {};
    encoderConfig.bit0.level0 = 1;
    encoderConfig.bit0.duration0 = 3;
    encoderConfig.bit0.level1 = 0;
    encoderConfig.bit0.duration1 = 9;
    encoderConfig.bit1.level0 = 1;
    encoderConfig.bit1.duration0 = 9;
    encoderConfig.bit1.level1 = 0;
    encoderConfig.bit1.duration1 = 3;
    encoderConfig.flags.msb_first = 1;

    static constexpr uint8_t kOff[3] = {};
    rmt_channel_handle_t channel = nullptr;
    rmt_encoder_handle_t encoder = nullptr;
    if (rmt_new_tx_channel(&channelConfig, &channel) == ESP_OK) {
        if (rmt_new_bytes_encoder(&encoderConfig, &encoder) == ESP_OK &&
            rmt_enable(channel) == ESP_OK) {
            const rmt_transmit_config_t transmitConfig = {};
            if (rmt_transmit(channel, encoder, kOff, sizeof(kOff),
                             &transmitConfig) == ESP_OK) {
                rmt_tx_wait_all_done(channel, 100);
            }
            rmt_disable(channel);
        }
        if (encoder != nullptr) {
            rmt_del_encoder(encoder);
        }
        rmt_del_channel(channel);
    }
    gpio_set_level(kPin, 0);
    gpio_set_direction(kPin, GPIO_MODE_OUTPUT);
}

extern "C" void app_main() {
    darkenBoardLed();
#if defined(DESKID_PRODUCTION)
    ESP_ERROR_CHECK(esp_efuse_is_flash_encryption_enabled()
                        ? ESP_OK
                        : ESP_ERR_INVALID_STATE);
    ESP_ERROR_CHECK(esp_secure_boot_enabled() ? ESP_OK
                                              : ESP_ERR_INVALID_STATE);
#endif
    ESP_ERROR_CHECK(nvs_flash_init());

    static StoredPivCredential credential;
    ESP_ERROR_CHECK(credential.initialize());

    static R503Sensor sensor;
#if !defined(DESKID_BRINGUP_NO_SENSOR)
    // A miswired or dead sensor must not take USB down with it: without the
    // CCID interface there is no status object and no way to find out why.
    // Every match then fails closed, which is the safe direction.
    if (sensor.initialize(credential.sensorPassword(),
                          !credential.sensorProvisioned()) == ESP_OK) {
        ESP_ERROR_CHECK(credential.markSensorProvisioned());
    }
#endif

    static deskid::RateLimiter presenceLimiter(
        kFingerprintFailureThreshold, kFingerprintBaseLockoutMilliseconds,
        kFingerprintMaximumLockoutMilliseconds);
    static NvsLimiterStore limiterStore;
    limiterStore.load(presenceLimiter);
    static deskid::AttemptLedger attempts(presenceLimiter, limiterStore);
    static BoardDiagnostics diagnostics(credential, sensor, presenceLimiter);
    static deskid::PivApplet applet(credential, diagnostics);
    ESP_ERROR_CHECK(deskid::installCcidDevice());

    static deskid::CcidRequest request;
    static uint8_t response[deskid::CcidRequest::kMaximumApduLength];
    uint32_t observedPowerEpoch = deskid::ccidPowerEpoch();
    int64_t nextRecovery = 0;
    int64_t nextArmedScan = 0;
    while (true) {
        sensor.serviceRing();
        if (!deskid::waitForCcidRequest(request, kIdleScanMilliseconds)) {
            // Nothing from the host, so the ring belongs to the user.
            const int64_t now = esp_timer_get_time();
            uint8_t autotypeSeconds = 0;
            bool autotypeToWake = false;
            if (deskid::takeAutotypeArm(autotypeSeconds, autotypeToWake)) {
                const uint64_t nowMs = millisecondsSinceBoot();
                if (g_autotype.arm(autotypeSeconds, nowMs, autotypeToWake)) {
                    // A match woke the display, and the host now says the
                    // lock screen is lit and still locked.
                    vTaskDelay(pdMS_TO_TICKS(kAutotypeLitMilliseconds));
                    typeDummyPin();
                }
                // An armed board has to be watching its ring, wake line or
                // not.
                g_ringArmedUntilMs = std::max<uint64_t>(
                    g_ringArmedUntilMs,
                    nowMs + g_autotype.secondsRemaining(nowMs) * 1000ULL);
            }
            if (g_autotype.retype(millisecondsSinceBoot())) {
                // The first digits met a display that was still coming up.
                typeDummyPin();
            }
            deskid::publishAutotypeStatus(
                g_autotype.secondsRemaining(millisecondsSinceBoot()),
                g_autotype.emissions(), sensor.wakeLineUsable());
            if (sensor.state() == 2 && now >= nextRecovery) {
                nextRecovery = now + 2000000;
                sensor.recover();
            }
            sensor.observeWakeLine();
            if (applet.enrollmentOpen()) {
                // The ring belongs to the enrollment. The finger on it is
                // new, and matching it would spend attempts on a finger that
                // cannot match yet.
                continue;
            }
            if (sensor.wakeLineUsable()) {
                scanForEarlyTouch(sensor, presenceLimiter, attempts);
            } else if (ringArmed() && now >= nextArmedScan) {
                nextArmedScan =
                    now + static_cast<int64_t>(kArmedScanMilliseconds) * 1000LL;
                scanForEarlyTouch(sensor, presenceLimiter, attempts);
            }
            continue;
        }

        const uint32_t requestPowerEpoch = request.powerEpoch;
        // A request the host re-powered the card under, or withdrew, is not
        // run at all: some instructions need no fingerprint, and running them
        // for a host that has stopped listening only desynchronises the two.
        if (deskid::ccidPowerEpoch() != requestPowerEpoch ||
            deskid::ccidRequestWasAborted(request)) {
            secureZero(request.apdu, request.apduLength);
            request.apduLength = 0;
            continue;
        }
        if (requestPowerEpoch != observedPowerEpoch) {
            applet.reset();
            observedPowerEpoch = requestPowerEpoch;
        }

        size_t responseLength = 0;
        deskid::TransceiveStatus transceiveStatus = applet.transceive(
            request.apdu, request.apduLength, false, response,
            sizeof(response), responseLength);
        if (transceiveStatus ==
            deskid::TransceiveStatus::userPresenceRequired) {
            if (authorizeFingerprint(sensor, presenceLimiter, attempts,
                                     request, requestPowerEpoch)) {
                transceiveStatus = applet.transceive(
                    request.apdu, request.apduLength, true, response,
                    sizeof(response), responseLength);
            } else {
                response[0] = 0x69;
                response[1] = presenceLimiter.locked(millisecondsSinceBoot())
                                  ? 0x83
                                  : 0x82;
                responseLength = 2;
                transceiveStatus = deskid::TransceiveStatus::complete;
            }
        }

        if (transceiveStatus != deskid::TransceiveStatus::complete ||
            deskid::ccidRequestWasAborted(request) ||
            deskid::ccidPowerEpoch() != requestPowerEpoch) {
            diagnostics.rebootIfRequested();
            secureZero(request.apdu, request.apduLength);
            request.apduLength = 0;
            continue;
        }
        for (size_t attempt = 0; attempt < 4; ++attempt) {
            if (deskid::sendCcidResponse(request, response,
                                         responseLength)) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(25));
        }
        diagnostics.rebootIfRequested();
        secureZero(request.apdu, request.apduLength);
        request.apduLength = 0;
    }
}