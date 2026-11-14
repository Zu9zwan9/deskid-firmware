// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

#include <unity.h>

#include <array>
#include <cstring>

#include "deskid_core.h"

namespace {

class FakeCredential final : public deskid::PivCredential {
public:
    FakeCredential() { reset(); }

    void reset() {
        for (size_t index = 0; index < certificate_.size(); ++index) {
            certificate_[index] = static_cast<uint8_t>(index);
        }
        certificateLength_ = certificate_.size();
        for (size_t index = 0; index < keyManagementCertificate_.size();
             ++index) {
            keyManagementCertificate_[index] =
                static_cast<uint8_t>(0xA0 ^ index);
        }
        keyManagementCertificateLength_ = keyManagementCertificate_.size();
        generatedKeys = 0;
        generatedKeyManagementKeys = 0;
        agreements = 0;
        signedMessageLength = 0;
    }

    void forget() { certificateLength_ = 0; }
    void forgetKeyManagement() { keyManagementCertificateLength_ = 0; }

    deskid::Bytes certificateDer(deskid::Slot slot) const override {
        if (slot == deskid::Slot::keyManagement) {
            return {keyManagementCertificate_.data(),
                    keyManagementCertificateLength_};
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
        constexpr uint8_t value[] = {0x30, 0x06, 0x02, 0x01,
                                     0x01, 0x02, 0x01, 0x02};
        if (digest.size != 32 || capacity < sizeof(value)) {
            return false;
        }
        std::memcpy(signature, value, sizeof(value));
        signatureLength = sizeof(value);
        return true;
    }

    // Stands in for hashing and signing a message: keeps the message, and
    // answers with a signature no digest path returns.
    bool signMessageP256Sha256(deskid::Bytes message, uint8_t *signature,
                               size_t capacity,
                               size_t &signatureLength) override {
        constexpr uint8_t value[] = {0x30, 0x06, 0x02, 0x01,
                                     0x03, 0x02, 0x01, 0x04};
        signatureLength = 0;
        if (message.size > signedMessage.size() || capacity < sizeof(value)) {
            return false;
        }
        std::memcpy(signedMessage.data(), message.data, message.size);
        signedMessageLength = message.size;
        std::memcpy(signature, value, sizeof(value));
        signatureLength = sizeof(value);
        return true;
    }

    // Stands in for ECDH: the "secret" is the peer's X coordinate with every
    // byte flipped, so a test can tell it came from the point it sent.
    bool agreeP256(deskid::Bytes peerPoint, uint8_t *secret, size_t capacity,
                   size_t &secretLength) override {
        secretLength = 0;
        if (peerPoint.size != 65 || peerPoint.data[0] != 0x04 ||
            capacity < 32) {
            return false;
        }
        for (size_t index = 0; index < 32; ++index) {
            secret[index] = static_cast<uint8_t>(~peerPoint.data[1 + index]);
        }
        secretLength = 32;
        ++agreements;
        return true;
    }

    bool generateKeyP256(deskid::Slot slot, uint8_t *publicKey,
                         size_t capacity, size_t &publicKeyLength) override {
        publicKeyLength = 0;
        if (capacity < 65) {
            return false;
        }
        publicKey[0] = 0x04;
        for (size_t index = 1; index < 65; ++index) {
            publicKey[index] = static_cast<uint8_t>(index);
        }
        publicKeyLength = 65;
        ++(slot == deskid::Slot::keyManagement ? generatedKeyManagementKeys
                                               : generatedKeys);
        return true;
    }

    bool storeCertificate(deskid::Slot slot,
                          deskid::Bytes certificateDer) override {
        const bool keyManagement = slot == deskid::Slot::keyManagement;
        auto &storage = keyManagement ? keyManagementCertificate_ : certificate_;
        if (certificateDer.size == 0 || certificateDer.size > storage.size()) {
            return false;
        }
        std::memcpy(storage.data(), certificateDer.data, certificateDer.size);
        (keyManagement ? keyManagementCertificateLength_ : certificateLength_) =
            certificateDer.size;
        return true;
    }

    size_t generatedKeys = 0;
    size_t generatedKeyManagementKeys = 0;
    size_t agreements = 0;
    std::array<uint8_t, 64> signedMessage{};
    size_t signedMessageLength = 0;

private:
    std::array<uint8_t, 300> certificate_{};
    std::array<uint8_t, 300> keyManagementCertificate_{};
    std::array<uint8_t, 16> identifier_{};
    size_t certificateLength_ = 0;
    size_t keyManagementCertificateLength_ = 0;
};

class FakeDiagnostics final : public deskid::DeviceDiagnostics {
public:
    deskid::DeviceStatus status() const override {
        deskid::DeviceStatus value;
        value.firmwareVersion = firmwareVersion;
        value.buildVariant = 2;
        value.uptimeSeconds = 0x00010203;
        value.resetReason = 4;
        value.freeHeapBytes = 0x0004ABCD;
        value.sensorState = 1;
        value.lastSensorConfirmation = 0x09;
        value.credentialPresent = true;
        value.consecutiveFailures = 3;
        value.lockoutSecondsRemaining = 42;
        value.enrolledTemplates = enrolledTemplates;
        value.templateCountKnown = templateCountKnown;
        value.wakeLineHigh = true;
        value.lastMatchMilliseconds = 1234;
        value.earlyTouchGates = 7;
        value.touchValidSecondsRemaining = 11;
        value.wakeLineBias = 0b10;
        value.ringArmedSecondsRemaining = 42;
        value.signingSelfTestPassed = signingSelfTestPassed;
        return value;
    }

    uint64_t uptimeMilliseconds() const override {
        return epochMilliseconds + nowMilliseconds;
    }

    bool enterDownloadMode() override {
        ++downloadModeRequests;
        return downloadModeSupported;
    }

    bool enrollStep(uint8_t &stage) override {
        ++enrollRequests;
        stage = enrollStage;
        return enrollSupported;
    }

    bool armRing(uint8_t seconds) override {
        armedSeconds = seconds;
        return true;
    }

    bool forgetFingerprints() override {
        ++forgetRequests;
        if (forgetSupported) {
            enrolledTemplates = 0;
        }
        return forgetSupported;
    }

    size_t downloadModeRequests = 0;
    bool downloadModeSupported = true;
    uint8_t armedSeconds = 0;
    size_t enrollRequests = 0;
    uint8_t enrollStage = 3;
    bool enrollSupported = true;
    size_t forgetRequests = 0;
    bool forgetSupported = true;
    uint32_t enrolledTemplates = 2;
    bool templateCountKnown = true;
    uint64_t nowMilliseconds = 0;
    // A board's clock never restarts. setUp() moves this on an hour, so what
    // one test left time-bound in the applet has run out before the next.
    uint64_t epochMilliseconds = 0;
    const char *firmwareVersion = "9.9.9";
    bool signingSelfTestPassed = true;
};

// NVS as the limiter sees it: what was last written is all that survives a
// pulled plug.
class FakeLimiterStore final : public deskid::LimiterStore {
public:
    bool save(uint32_t consecutiveFailures, uint32_t lockoutCount) override {
        if (!healthy) {
            return false;
        }
        failures = consecutiveFailures;
        lockouts = lockoutCount;
        ++writes;
        return true;
    }

    bool healthy = true;
    uint32_t failures = 0;
    uint32_t lockouts = 0;
    size_t writes = 0;
};

FakeCredential credential;
FakeDiagnostics diagnostics;
deskid::PivApplet applet(credential, diagnostics);
std::array<uint8_t, 512> response{};

void selectApplet() {
    constexpr uint8_t select[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xF0, 0x44,
                                  0x65, 0x73, 0x6B, 0x49, 0x44};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(select, sizeof(select), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_HEX8(0x90, response[responseLength - 2]);
    TEST_ASSERT_EQUAL_HEX8(0x00, response[responseLength - 1]);
}

}  // namespace

// Unity ships weak no-op fixtures, so a setUp() inside the anonymous namespace
// above would be silently ignored and the tests would leak state into each
// other.
void setUp() {
    applet.reset();
    credential.reset();
    diagnostics.downloadModeSupported = true;
    diagnostics.enrollSupported = true;
    diagnostics.forgetSupported = true;
    diagnostics.forgetRequests = 0;
    diagnostics.downloadModeRequests = 0;
    diagnostics.enrolledTemplates = 2;
    diagnostics.templateCountKnown = true;
    diagnostics.nowMilliseconds = 0;
    diagnostics.epochMilliseconds += 3600000;
    diagnostics.firmwareVersion = "9.9.9";
    diagnostics.signingSelfTestPassed = true;
    response.fill(0);
}

void tearDown() {}

namespace {

void test_selects_standard_piv_aid() {
    selectApplet();
    constexpr uint8_t expected[] = {
        0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
        0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08,
    };
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(), sizeof(expected));
}

void test_certificate_response_is_chained_without_truncation() {
    selectApplet();
    constexpr uint8_t getCertificate[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00,
    };
    std::array<uint8_t, 320> reassembled{};
    size_t reassembledLength = 0;
    size_t responseLength = 0;
    applet.transceive(getCertificate, sizeof(getCertificate), false,
                      response.data(), response.size(), responseLength);
    TEST_ASSERT_EQUAL_UINT32(258, responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x61, response[256]);
    std::memcpy(reassembled.data(), response.data(), 256);
    reassembledLength = 256;

    constexpr uint8_t getResponseShort[] = {0x00, 0xC0, 0x00, 0x00, 0x10};
    applet.transceive(getResponseShort, sizeof(getResponseShort), false,
                      response.data(), response.size(), responseLength);
    TEST_ASSERT_EQUAL_UINT32(18, responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x61, response[16]);
    std::memcpy(reassembled.data() + reassembledLength, response.data(), 16);
    reassembledLength += 16;

    constexpr uint8_t getResponse[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
    applet.transceive(getResponse, sizeof(getResponse), false, response.data(),
                      response.size(), responseLength);
    TEST_ASSERT_GREATER_THAN_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x90, response[responseLength - 2]);
    TEST_ASSERT_EQUAL_HEX8(0x00, response[responseLength - 1]);
    std::memcpy(reassembled.data() + reassembledLength, response.data(),
                responseLength - 2);
    reassembledLength += responseLength - 2;

    TEST_ASSERT_EQUAL_UINT32(313, reassembledLength);
    constexpr uint8_t header[] = {0x53, 0x82, 0x01, 0x35,
                                  0x70, 0x82, 0x01, 0x2C};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(header, reassembled.data(), sizeof(header));
    for (size_t index = 0; index < 300; ++index) {
        TEST_ASSERT_EQUAL_HEX8(static_cast<uint8_t>(index),
                               reassembled[8 + index]);
    }
    constexpr uint8_t trailer[] = {0x71, 0x01, 0x00, 0xFE, 0x00};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(trailer, reassembled.data() + 308,
                                  sizeof(trailer));
}

void test_public_card_objects_include_device_identifier() {
    selectApplet();
    constexpr uint8_t getChuid[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x00,
    };
    size_t responseLength = 0;
    applet.transceive(getChuid, sizeof(getChuid), false, response.data(),
                      response.size(), responseLength);
    TEST_ASSERT_EQUAL_UINT32(63, responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x53, response[0]);
    TEST_ASSERT_EQUAL_HEX8(0x3B, response[1]);
    TEST_ASSERT_EQUAL_HEX8(0x40, response[37]);
    TEST_ASSERT_EQUAL_HEX8(0x80, response[39]);

    constexpr uint8_t getCcc[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x07, 0x00,
    };
    applet.transceive(getCcc, sizeof(getCcc), false, response.data(),
                      response.size(), responseLength);
    TEST_ASSERT_EQUAL_UINT32(55, responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x53, response[0]);
    TEST_ASSERT_EQUAL_HEX8(0x33, response[1]);
    TEST_ASSERT_EQUAL_HEX8(0x90, response[responseLength - 2]);
}

void test_general_authenticate_waits_for_user_presence() {
    selectApplet();
    std::array<uint8_t, 44> authenticate = {
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    for (size_t index = 0; index < 32; ++index) {
        authenticate[11 + index] = static_cast<uint8_t>(index);
    }
    authenticate[43] = 0x00;

    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(authenticate.data(), authenticate.size(),
                                        false, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(0, responseLength);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(authenticate.data(), authenticate.size(),
                                        true, response.data(), response.size(),
                                        responseLength));
    constexpr uint8_t expected[] = {0x7C, 0x0A, 0x82, 0x08, 0x30, 0x06,
                                    0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
                                    0x90, 0x00};
    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(), sizeof(expected));
}

void test_verify_authorizes_exactly_one_signature() {
    selectApplet();
    constexpr uint8_t verify[] = {
        0x00, 0x20, 0x00, 0x80, 0x08, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(verify, sizeof(verify), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(verify, sizeof(verify), true,
                                        response.data(), response.size(),
                                        responseLength));

    std::array<uint8_t, 44> authenticate = {
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    authenticate[43] = 0x00;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(authenticate.data(), authenticate.size(),
                                        false, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(authenticate.data(), authenticate.size(),
                                        false, response.data(), response.size(),
                                        responseLength));
}

void test_verify_status_query_does_not_request_a_fingerprint() {
    selectApplet();
    constexpr uint8_t verifyStatus[] = {0x00, 0x20, 0x00, 0x80};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(verifyStatus, sizeof(verifyStatus),
                                        false, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x63, response[0]);
    TEST_ASSERT_EQUAL_HEX8(0xC3, response[1]);
}

void test_generate_key_pair_is_gated_and_returns_public_point() {
    selectApplet();
    constexpr uint8_t generate[] = {0x00, 0x47, 0x00, 0x9A, 0x05,
                                    0xAC, 0x03, 0x80, 0x01, 0x11, 0x00};
    const size_t before = credential.generatedKeys;
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(generate, sizeof(generate), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(before, credential.generatedKeys);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(generate, sizeof(generate), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(before + 1, credential.generatedKeys);
    TEST_ASSERT_EQUAL_UINT32(72, responseLength);
    constexpr uint8_t header[] = {0x7F, 0x49, 0x43, 0x86, 0x41, 0x04};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(header, response.data(), sizeof(header));
    TEST_ASSERT_EQUAL_HEX8(0x90, response[70]);
    TEST_ASSERT_EQUAL_HEX8(0x00, response[71]);
}

void test_generate_key_pair_rejects_non_p256_algorithm() {
    selectApplet();
    constexpr uint8_t generate[] = {0x00, 0x47, 0x00, 0x9A, 0x05,
                                    0xAC, 0x03, 0x80, 0x01, 0x07, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(generate, sizeof(generate), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6A80, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_put_data_is_gated_and_replaces_certificate() {
    selectApplet();
    constexpr uint8_t putCertificate[] = {
        0x00, 0xDB, 0x3F, 0xFF, 0x14, 0x5C, 0x03, 0x5F, 0xC1,
        0x05, 0x53, 0x0D, 0x70, 0x06, 0xA1, 0xA2, 0xA3, 0xA4,
        0xA5, 0xA6, 0x71, 0x01, 0x00, 0xFE, 0x00,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(putCertificate, sizeof(putCertificate),
                                        false, response.data(),
                                        response.size(), responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(putCertificate, sizeof(putCertificate),
                                        true, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x9000, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));

    constexpr uint8_t getCertificate[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00,
    };
    applet.transceive(getCertificate, sizeof(getCertificate), false,
                      response.data(), response.size(), responseLength);
    constexpr uint8_t expected[] = {0x53, 0x0D, 0x70, 0x06, 0xA1, 0xA2,
                                    0xA3, 0xA4, 0xA5, 0xA6, 0x71, 0x01,
                                    0x00, 0xFE, 0x00, 0x90, 0x00};
    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(),
                                  sizeof(expected));
}

void test_put_data_rejects_unknown_object() {
    selectApplet();
    constexpr uint8_t putUnknown[] = {
        0x00, 0xDB, 0x3F, 0xFF, 0x0B, 0x5C, 0x03, 0x5F, 0xC1,
        0x0A, 0x53, 0x04, 0x70, 0x02, 0xA1, 0xA2,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(putUnknown, sizeof(putUnknown), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6A82, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_unprovisioned_board_serves_no_public_objects() {
    credential.forget();
    selectApplet();
    constexpr uint8_t objects[][11] = {
        {0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00},
        {0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x00},
        {0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x07, 0x00},
    };
    for (const auto &object : objects) {
        size_t responseLength = 0;
        TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                          applet.transceive(object, sizeof(object), false,
                                            response.data(), response.size(),
                                            responseLength));
        TEST_ASSERT_EQUAL_UINT32(2, responseLength);
        TEST_ASSERT_EQUAL_HEX16(
            0x6A82, static_cast<uint16_t>(response[0] << 8 | response[1]));
    }
}

// A factory board has no identity and no enrolled finger, so provisioning has
// to run without one. The window has to shut the moment the certificate lands,
// or any host could replace the identity for the life of the device.
void test_unprovisioned_board_provisions_without_a_fingerprint() {
    credential.forget();
    selectApplet();
    constexpr uint8_t generate[] = {0x00, 0x47, 0x00, 0x9A, 0x05,
                                    0xAC, 0x03, 0x80, 0x01, 0x11, 0x00};
    constexpr uint8_t putCertificate[] = {
        0x00, 0xDB, 0x3F, 0xFF, 0x14, 0x5C, 0x03, 0x5F, 0xC1,
        0x05, 0x53, 0x0D, 0x70, 0x06, 0xA1, 0xA2, 0xA3, 0xA4,
        0xA5, 0xA6, 0x71, 0x01, 0x00, 0xFE, 0x00,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(generate, sizeof(generate), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(1, credential.generatedKeys);
    TEST_ASSERT_EQUAL_UINT32(72, responseLength);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(putCertificate, sizeof(putCertificate),
                                        false, response.data(),
                                        response.size(), responseLength));
    TEST_ASSERT_EQUAL_HEX16(0x9000, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(generate, sizeof(generate), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(putCertificate, sizeof(putCertificate),
                                        false, response.data(),
                                        response.size(), responseLength));
    TEST_ASSERT_EQUAL_UINT32(1, credential.generatedKeys);
}

void test_unprovisioned_board_refuses_to_sign_without_waiting() {
    credential.forget();
    selectApplet();
    std::array<uint8_t, 44> authenticate = {
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    authenticate[43] = 0x00;
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(authenticate.data(),
                                        authenticate.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6A88, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_rate_limiter_locks_backs_off_and_resets() {
    deskid::RateLimiter limiter(3, 1000, 4000);

    limiter.recordFailure(0);
    limiter.recordFailure(0);
    TEST_ASSERT_FALSE(limiter.locked(0));
    limiter.recordFailure(0);
    TEST_ASSERT_TRUE(limiter.locked(0));
    TEST_ASSERT_TRUE(limiter.locked(999));
    TEST_ASSERT_FALSE(limiter.locked(1000));

    limiter.recordFailure(1000);
    limiter.recordFailure(1000);
    limiter.recordFailure(1000);
    TEST_ASSERT_TRUE(limiter.locked(2999));
    TEST_ASSERT_FALSE(limiter.locked(3000));

    limiter.recordFailure(3000);
    limiter.recordFailure(3000);
    limiter.recordFailure(3000);
    TEST_ASSERT_TRUE(limiter.locked(6999));
    TEST_ASSERT_FALSE(limiter.locked(7000));

    limiter.recordSuccess();
    limiter.recordFailure(7000);
    limiter.recordFailure(7000);
    TEST_ASSERT_FALSE(limiter.locked(7000));
    limiter.recordFailure(7000);
    TEST_ASSERT_TRUE(limiter.locked(7999));
    TEST_ASSERT_FALSE(limiter.locked(8000));
}

// Unplugging the device is the cheapest attack there is, so a restored lockout
// is re-armed in full and the failure count picks up where it left off.
void test_lockout_survives_a_power_cycle() {
    deskid::RateLimiter limiter(3, 1000, 4000);
    limiter.recordFailure(0);
    limiter.recordFailure(0);
    limiter.recordFailure(0);
    TEST_ASSERT_TRUE(limiter.locked(0));
    TEST_ASSERT_EQUAL_UINT32(1, limiter.lockoutCount());

    deskid::RateLimiter rebooted(3, 1000, 4000);
    rebooted.restore(limiter.consecutiveFailures(), limiter.lockoutCount(), 0);
    TEST_ASSERT_TRUE(rebooted.locked(999));
    TEST_ASSERT_FALSE(rebooted.locked(1000));
    rebooted.recordFailure(1000);
    rebooted.recordFailure(1000);
    rebooted.recordFailure(1000);
    TEST_ASSERT_TRUE(rebooted.locked(2999));
    TEST_ASSERT_FALSE(rebooted.locked(3000));

    deskid::RateLimiter resumed(3, 1000, 4000);
    resumed.restore(2, 0, 0);
    TEST_ASSERT_FALSE(resumed.locked(0));
    resumed.recordFailure(0);
    TEST_ASSERT_TRUE(resumed.locked(0));
}

void test_rejects_malformed_authentication_template() {
    selectApplet();
    constexpr uint8_t malformed[] = {0x00, 0x87, 0x11, 0x9A, 0x04,
                                     0x7C, 0x02, 0x82, 0x00};
    size_t responseLength = 0;
    applet.transceive(malformed, sizeof(malformed), true, response.data(),
                      response.size(), responseLength);
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6A80,
                            static_cast<uint16_t>(response[0] << 8 | response[1]));
}

void test_piv_aid_is_refused_unless_allowed() {
    constexpr uint8_t select[] = {0x00, 0xA4, 0x04, 0x00, 0x05,
                                  0xA0, 0x00, 0x00, 0x03, 0x08};
    size_t responseLength = 0;
    applet.transceive(select, sizeof(select), false, response.data(),
                      response.size(), responseLength);
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6A82,
                            static_cast<uint16_t>(response[0] << 8 | response[1]));
}

void test_status_object_reports_device_state_without_user_presence() {
    selectApplet();
    constexpr uint8_t getStatus[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x00,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(getStatus, sizeof(getStatus), false,
                                        response.data(), response.size(),
                                        responseLength));
    constexpr uint8_t expected[] = {
        0x53, 0x5A, 0x01, 0x05, 0x39, 0x2E, 0x39, 0x2E, 0x39, 0x02, 0x01,
        0x02, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x01, 0x04, 0x05,
        0x04, 0x00, 0x04, 0xAB, 0xCD, 0x06, 0x01, 0x01, 0x07, 0x01, 0x09,
        0x08, 0x01, 0x01, 0x09, 0x01, 0x03, 0x0A, 0x04, 0x00, 0x00, 0x00,
        0x2A, 0x0B, 0x04, 0x00, 0x00, 0x00, 0x02, 0x0C, 0x01, 0x01, 0x0D,
        0x04, 0x00, 0x00, 0x04, 0xD2, 0x0E, 0x01, 0x00, 0x0F, 0x01, 0x00,
        0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x00, 0x00, 0x00,
        0x07, 0x12, 0x01, 0x0B, 0x13, 0x01, 0x02, 0x14, 0x01, 0x2A,
        0x15, 0x01, 0x01, 0xFE, 0x00, 0x90, 0x00,
    };
    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(), sizeof(expected));
}

void test_download_mode_is_gated_by_user_presence() {
    selectApplet();
    constexpr uint8_t downloadMode[] = {0x80, 0xF0, 0x00, 0x00, 0x00};
    const size_t before = diagnostics.downloadModeRequests;
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(downloadMode, sizeof(downloadMode),
                                        false, response.data(),
                                        response.size(), responseLength));
    TEST_ASSERT_EQUAL_UINT32(before, diagnostics.downloadModeRequests);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(downloadMode, sizeof(downloadMode),
                                        true, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(before + 1, diagnostics.downloadModeRequests);
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x9000, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_download_mode_declined_reports_unsupported_instruction() {
    selectApplet();
    diagnostics.downloadModeSupported = false;
    constexpr uint8_t downloadMode[] = {0x80, 0xF0, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(downloadMode, sizeof(downloadMode),
                                        true, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6D00, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_enrollment_is_open_while_the_sensor_library_is_empty() {
    selectApplet();
    diagnostics.enrolledTemplates = 0;
    diagnostics.enrollStage = 1;
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    const size_t before = diagnostics.enrollRequests;
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(enroll, sizeof(enroll), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(before + 1, diagnostics.enrollRequests);
    constexpr uint8_t expected[] = {0x01, 0x90, 0x00};
    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(), sizeof(expected));
}

void test_enrollment_requires_a_match_once_a_finger_is_enrolled() {
    selectApplet();
    diagnostics.enrollStage = 3;
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    const size_t before = diagnostics.enrollRequests;
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(enroll, sizeof(enroll), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(before, diagnostics.enrollRequests);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(enroll, sizeof(enroll), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(before + 1, diagnostics.enrollRequests);
    constexpr uint8_t expected[] = {0x03, 0x90, 0x00};
    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(), sizeof(expected));
}

void test_enrollment_declined_reports_unsupported_instruction() {
    selectApplet();
    diagnostics.enrolledTemplates = 0;
    diagnostics.enrollSupported = false;
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(enroll, sizeof(enroll), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6D00, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_forgetting_fingerprints_requires_a_match() {
    selectApplet();
    constexpr uint8_t forget[] = {0x80, 0xE2, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(forget, sizeof(forget), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.forgetRequests);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(forget, sizeof(forget), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.forgetRequests);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.enrolledTemplates);
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x9000, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

// An empty library cannot produce the match that would authorize emptying it,
// so the request has to succeed on its own rather than deadlock the recovery.
void test_forgetting_an_empty_library_needs_no_match() {
    selectApplet();
    diagnostics.enrolledTemplates = 0;
    constexpr uint8_t forget[] = {0x80, 0xE2, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(forget, sizeof(forget), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.forgetRequests);
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x9000, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_forgetting_declined_reports_unsupported_instruction() {
    selectApplet();
    diagnostics.forgetSupported = false;
    constexpr uint8_t forget[] = {0x80, 0xE2, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(forget, sizeof(forget), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6D00, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

}  // namespace

void test_early_touch_answers_only_the_login_instructions() {
    deskid::EarlyTouch touch(15000);
    TEST_ASSERT_FALSE(touch.held(1000));
    TEST_ASSERT_FALSE(touch.spend(0x87, 1000));

    touch.record(1000);
    TEST_ASSERT_TRUE(touch.held(1000));
    // Enrolling a finger, writing a key or a certificate, emptying the sensor
    // and rebooting into download mode all still cost a live match.
    TEST_ASSERT_FALSE(touch.spend(0xE1, 2000));
    TEST_ASSERT_FALSE(touch.spend(0xE2, 2000));
    TEST_ASSERT_FALSE(touch.spend(0x47, 2000));
    TEST_ASSERT_FALSE(touch.spend(0xDB, 2000));
    TEST_ASSERT_FALSE(touch.spend(0xF0, 2000));
    TEST_ASSERT_TRUE(touch.held(2000));
    TEST_ASSERT_EQUAL_UINT32(0, touch.gates());

    TEST_ASSERT_TRUE(touch.spend(0x20, 2000));
    TEST_ASSERT_EQUAL_UINT32(1, touch.gates());
}

void test_early_touch_is_single_use_and_expires() {
    deskid::EarlyTouch touch(15000);
    touch.record(1000);
    TEST_ASSERT_TRUE(touch.spend(0x87, 1100));
    // One touch is one operation: a second signature has to be asked for.
    TEST_ASSERT_FALSE(touch.spend(0x87, 1100));
    TEST_ASSERT_FALSE(touch.held(1100));
    TEST_ASSERT_EQUAL_UINT64(0, touch.millisecondsRemaining(1100));

    touch.record(2000);
    TEST_ASSERT_EQUAL_UINT64(15000, touch.millisecondsRemaining(2000));
    TEST_ASSERT_EQUAL_UINT64(1, touch.millisecondsRemaining(16999));
    // The window is the security trade, so it has to actually close.
    TEST_ASSERT_FALSE(touch.held(17000));
    TEST_ASSERT_FALSE(touch.spend(0x87, 17000));
    TEST_ASSERT_EQUAL_UINT32(1, touch.gates());

    touch.record(20000);
    touch.clear();
    TEST_ASSERT_FALSE(touch.held(20000));
}

void test_arm_ring_needs_no_fingerprint_and_takes_a_duration() {
    selectApplet();
    // Arming releases nothing and reveals nothing — it only asks the board to
    // look at its own sensor — so demanding a match to ask for one would mean
    // touching the ring to make the ring watchable.
    constexpr uint8_t arm[] = {0x80, 0xE3, 0x00, 0x00, 0x01, 0x3C};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(arm, sizeof(arm), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT8(0x90, response[0]);
    TEST_ASSERT_EQUAL_UINT8(0x00, response[1]);
    TEST_ASSERT_EQUAL_UINT8(0x3C, diagnostics.armedSeconds);

    constexpr uint8_t noDuration[] = {0x80, 0xE3, 0x00, 0x00, 0x00};
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(noDuration, sizeof(noDuration), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT8(0x6A, response[0]);
    TEST_ASSERT_EQUAL_UINT8(0x86, response[1]);
}

void test_selecting_the_applet_arms_the_ring() {
    diagnostics.armedSeconds = 0;
    // A fresh selection is the host saying it cares about this card now, which
    // at the lock screen is the moment the user walks up. Re-selecting an
    // already selected applet must not extend it, or a chatty host turns a
    // bounded window into a permanent one.
    selectApplet();
    TEST_ASSERT_EQUAL_UINT8(deskid::kArmOnSelectSeconds, diagnostics.armedSeconds);

    diagnostics.armedSeconds = 0;
    selectApplet();
    TEST_ASSERT_EQUAL_UINT8(0, diagnostics.armedSeconds);

    applet.reset();
    selectApplet();
    TEST_ASSERT_EQUAL_UINT8(deskid::kArmOnSelectSeconds, diagnostics.armedSeconds);
}

// The verdict is the secret. A limiter that counts a failure after hearing it
// can be starved by cutting power in between, so the attempt is charged, and
// written down, before the sensor is asked.
void test_attempt_is_charged_before_the_verdict_and_survives_power_loss() {
    FakeLimiterStore store;
    deskid::RateLimiter limiter(3, 1000, 4000);
    deskid::AttemptLedger ledger(limiter, store);

    TEST_ASSERT_TRUE(ledger.charge(0));
    TEST_ASSERT_EQUAL_UINT32(1, store.failures);
    TEST_ASSERT_TRUE(ledger.charge(0));
    TEST_ASSERT_EQUAL_UINT32(2, store.failures);

    // The plug is pulled here, with no verdict ever heard for either attempt.
    deskid::RateLimiter rebooted(3, 1000, 4000);
    rebooted.restore(store.failures, store.lockouts, 0);
    deskid::AttemptLedger afterReboot(rebooted, store);
    TEST_ASSERT_TRUE(afterReboot.charge(0));
    TEST_ASSERT_TRUE(rebooted.locked(0));
    TEST_ASSERT_EQUAL_UINT32(1, store.lockouts);
    TEST_ASSERT_FALSE(afterReboot.charge(0));
    TEST_ASSERT_FALSE(afterReboot.charge(999));
    TEST_ASSERT_TRUE(afterReboot.charge(1000));
}

void test_a_match_clears_the_charge_and_says_so_on_disk() {
    FakeLimiterStore store;
    deskid::RateLimiter limiter(3, 1000, 4000);
    deskid::AttemptLedger ledger(limiter, store);

    TEST_ASSERT_TRUE(ledger.charge(0));
    TEST_ASSERT_TRUE(ledger.charge(0));
    // The last permitted attempt arms the lockout before its verdict, and a
    // match must still be able to clear it.
    TEST_ASSERT_TRUE(ledger.charge(0));
    TEST_ASSERT_TRUE(limiter.locked(0));
    ledger.matched();
    TEST_ASSERT_FALSE(limiter.locked(0));
    TEST_ASSERT_EQUAL_UINT32(0, store.failures);
    TEST_ASSERT_EQUAL_UINT32(0, store.lockouts);
}

// A resting finger is imaged up to three times, because the first image is
// often smeared. Charging each image made one touch cost three of the five
// attempts, and two imperfect touches locked a board out in eight seconds.
// One touch is one attempt.
void test_one_touch_is_one_charge_for_at_most_three_verdicts() {
    FakeLimiterStore store;
    deskid::RateLimiter limiter(3, 1000, 4000);
    deskid::AttemptLedger ledger(limiter, store);

    TEST_ASSERT_TRUE(ledger.chargeTouch(0));
    TEST_ASSERT_TRUE(ledger.chargeTouch(0));
    TEST_ASSERT_TRUE(ledger.chargeTouch(0));
    TEST_ASSERT_EQUAL_UINT32(1, store.failures);
    TEST_ASSERT_EQUAL_UINT32(1, store.writes);
    // A fourth image of the same touch is not put to the sensor at all.
    TEST_ASSERT_FALSE(ledger.chargeTouch(0));

    ledger.touchEnded();
    TEST_ASSERT_TRUE(ledger.chargeTouch(0));
    TEST_ASSERT_EQUAL_UINT32(2, store.failures);
}

// The charge that arms the lockout still gets its own verdict, as charge()
// allows, but no further image of that touch. A match frees the finger to be
// asked about again, at the price of a new charge.
void test_a_touch_stops_riding_once_locked_out_and_a_match_starts_over() {
    FakeLimiterStore store;
    deskid::RateLimiter limiter(2, 1000, 4000);
    deskid::AttemptLedger ledger(limiter, store);

    TEST_ASSERT_TRUE(ledger.chargeTouch(0));
    ledger.touchEnded();
    TEST_ASSERT_TRUE(ledger.chargeTouch(0));
    TEST_ASSERT_TRUE(limiter.locked(0));
    TEST_ASSERT_FALSE(ledger.chargeTouch(0));

    ledger.matched();
    TEST_ASSERT_TRUE(ledger.chargeTouch(0));
    TEST_ASSERT_EQUAL_UINT32(1, store.failures);
}

void test_an_attempt_that_cannot_be_written_down_is_refused() {
    FakeLimiterStore store;
    store.healthy = false;
    deskid::RateLimiter limiter(3, 1000, 4000);
    deskid::AttemptLedger ledger(limiter, store);

    TEST_ASSERT_FALSE(ledger.charge(0));
    TEST_ASSERT_EQUAL_UINT32(0, store.writes);
    // Refused, but not forgotten: the attempt still counts in memory.
    TEST_ASSERT_EQUAL_UINT32(1, limiter.consecutiveFailures());
}

// "Zero templates" opens enrollment to anyone, so it has to be something the
// sensor said, not the value a counter happens to start at.
void test_enrollment_is_gated_while_the_template_count_is_unknown() {
    selectApplet();
    diagnostics.enrolledTemplates = 0;
    diagnostics.templateCountKnown = false;
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    const size_t before = diagnostics.enrollRequests;
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(enroll, sizeof(enroll), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(before, diagnostics.enrollRequests);

    constexpr uint8_t forget[] = {0x80, 0xE2, 0x00, 0x00, 0x00};
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(forget, sizeof(forget), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.forgetRequests);
}

// A verified touch is spent by the next signature, and it must not wait for
// one indefinitely: a card left selected would otherwise hold a signature in
// reserve for whichever process asks first.
void test_verify_expires_instead_of_waiting_for_a_signature() {
    selectApplet();
    constexpr uint8_t verify[] = {
        0x00, 0x20, 0x00, 0x80, 0x08, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    constexpr uint8_t verifyStatus[] = {0x00, 0x20, 0x00, 0x80};
    std::array<uint8_t, 44> authenticate = {
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    size_t responseLength = 0;

    diagnostics.nowMilliseconds = 5000;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(verify, sizeof(verify), true,
                                        response.data(), response.size(),
                                        responseLength));
    diagnostics.nowMilliseconds = 5000 + deskid::kVerifiedValidMilliseconds - 1;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(verifyStatus, sizeof(verifyStatus),
                                        false, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_HEX8(0x90, response[0]);

    diagnostics.nowMilliseconds = 5000 + deskid::kVerifiedValidMilliseconds;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(verifyStatus, sizeof(verifyStatus),
                                        false, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_HEX8(0x63, response[0]);
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(authenticate.data(), authenticate.size(),
                                        false, response.data(), response.size(),
                                        responseLength));
}

// The version field is allowed sixteen characters, so the object has to fit
// with all sixteen in it.
void test_status_object_fits_the_longest_version_string() {
    selectApplet();
    diagnostics.firmwareVersion = "10.20.30-rc1+abc";
    constexpr uint8_t getStatus[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x00,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(getStatus, sizeof(getStatus), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2 + 85 + 16 + 2, responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x53, response[0]);
    TEST_ASSERT_EQUAL_HEX8(85 + 16, response[1]);
    TEST_ASSERT_EQUAL_HEX8(0x90, response[responseLength - 2]);
}

// ---- slot 9D, key management ----------------------------------------------

// GENERAL AUTHENTICATE for slot 9D: 7C { 82 00, 85 41 <uncompressed point> }.
std::array<uint8_t, 76> keyAgreementRequest() {
    std::array<uint8_t, 76> request = {
        0x00, 0x87, 0x11, 0x9D, 0x47, 0x7C, 0x45,
        0x82, 0x00, 0x85, 0x41, 0x04,
    };
    for (size_t index = 12; index < request.size(); ++index) {
        request[index] = static_cast<uint8_t>(index);
    }
    return request;
}

void test_key_agreement_waits_for_a_fingerprint_and_returns_the_secret() {
    selectApplet();
    const auto request = keyAgreementRequest();
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(request.data(), request.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(0, credential.agreements);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(request.data(), request.size(), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(1, credential.agreements);
    TEST_ASSERT_EQUAL_UINT32(4 + 32 + 2, responseLength);
    constexpr uint8_t header[] = {0x7C, 0x22, 0x82, 0x20};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(header, response.data(), sizeof(header));
    for (size_t index = 0; index < 32; ++index) {
        TEST_ASSERT_EQUAL_HEX8(static_cast<uint8_t>(~request[12 + index]),
                               response[4 + index]);
    }
    TEST_ASSERT_EQUAL_HEX8(0x90, response[36]);
    TEST_ASSERT_EQUAL_HEX8(0x00, response[37]);
}

// A login is a signature and a key agreement: macOS proves the card with the
// first and unwraps the keychain password with the second. One touch buys
// that pair and no more of either.
void test_one_touch_buys_one_signature_and_one_key_agreement() {
    selectApplet();
    diagnostics.nowMilliseconds = 1000;
    constexpr uint8_t verify[] = {
        0x00, 0x20, 0x00, 0x80, 0x08, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    std::array<uint8_t, 44> sign = {
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    const auto agree = keyAgreementRequest();
    size_t responseLength = 0;
    auto send = [&](const uint8_t *apdu, size_t length, bool userPresent) {
        return applet.transceive(apdu, length, userPresent, response.data(),
                                 response.size(), responseLength);
    };
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      send(verify, sizeof(verify), true));

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      send(agree.data(), agree.size(), false));
    TEST_ASSERT_EQUAL_HEX8(0x7C, response[0]);
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      send(agree.data(), agree.size(), false));

    // The agreement did not spend the signature.
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      send(sign.data(), sign.size(), false));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      send(sign.data(), sign.size(), false));
}

// The driver asks for the signature with no VERIFY before it. The touch that
// paid for the signature covers the agreement of the same login.
void test_a_touch_spent_on_a_signature_covers_the_key_agreement_after_it() {
    selectApplet();
    diagnostics.nowMilliseconds = 1000;
    std::array<uint8_t, 44> sign = {
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    const auto agree = keyAgreementRequest();
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(sign.data(), sign.size(), true,
                                        response.data(), response.size(),
                                        responseLength));
    // The two halves may come through different card sessions.
    applet.reset();
    selectApplet();
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(agree.data(), agree.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(agree.data(), agree.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
}

// The pair is a login in progress, not a standing permission.
void test_the_key_agreement_a_touch_bought_expires_with_it() {
    selectApplet();
    diagnostics.nowMilliseconds = 1000;
    constexpr uint8_t verify[] = {
        0x00, 0x20, 0x00, 0x80, 0x08, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    const auto agree = keyAgreementRequest();
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(verify, sizeof(verify), true,
                                        response.data(), response.size(),
                                        responseLength));
    diagnostics.nowMilliseconds = 1000 + deskid::kAgreementValidMilliseconds;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(agree.data(), agree.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
}

void test_key_agreement_rejects_malformed_templates_without_waiting() {
    selectApplet();
    size_t responseLength = 0;
    auto expectWrongData = [&](const uint8_t *apdu, size_t length) {
        TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                          applet.transceive(apdu, length, false,
                                            response.data(), response.size(),
                                            responseLength));
        TEST_ASSERT_EQUAL_UINT32(2, responseLength);
        TEST_ASSERT_EQUAL_HEX16(0x6A80, static_cast<uint16_t>(
                                            response[0] << 8 | response[1]));
    };

    // A point one byte short.
    std::array<uint8_t, 75> shortPoint = {
        0x00, 0x87, 0x11, 0x9D, 0x46, 0x7C, 0x44,
        0x82, 0x00, 0x85, 0x40, 0x04,
    };
    expectWrongData(shortPoint.data(), shortPoint.size());

    // No response placeholder.
    std::array<uint8_t, 74> noPlaceholder = {
        0x00, 0x87, 0x11, 0x9D, 0x45, 0x7C, 0x43, 0x85, 0x41, 0x04,
    };
    expectWrongData(noPlaceholder.data(), noPlaceholder.size());

    // A signing template sent to the key management slot.
    std::array<uint8_t, 43> digestTemplate = {
        0x00, 0x87, 0x11, 0x9D, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    expectWrongData(digestTemplate.data(), digestTemplate.size());

    // A compressed point: the credential refuses it after the gate.
    auto compressed = keyAgreementRequest();
    compressed[11] = 0x02;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(compressed.data(), compressed.size(),
                                        true, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_HEX16(0x6A80, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
    TEST_ASSERT_EQUAL_UINT32(0, credential.agreements);
}

void test_key_agreement_is_refused_without_a_key_management_identity() {
    credential.forgetKeyManagement();
    selectApplet();
    const auto request = keyAgreementRequest();
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(request.data(), request.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(2, responseLength);
    TEST_ASSERT_EQUAL_HEX16(0x6A88, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));
}

void test_key_management_slot_generates_its_own_key_behind_the_gate() {
    selectApplet();
    constexpr uint8_t generate[] = {0x00, 0x47, 0x00, 0x9D, 0x05,
                                    0xAC, 0x03, 0x80, 0x01, 0x11, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(generate, sizeof(generate), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(generate, sizeof(generate), true,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(1, credential.generatedKeyManagementKeys);
    TEST_ASSERT_EQUAL_UINT32(0, credential.generatedKeys);
    TEST_ASSERT_EQUAL_UINT32(72, responseLength);
    constexpr uint8_t header[] = {0x7F, 0x49, 0x43, 0x86, 0x41, 0x04};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(header, response.data(), sizeof(header));
}

void test_key_management_certificate_has_its_own_object() {
    selectApplet();
    constexpr uint8_t putCertificate[] = {
        0x00, 0xDB, 0x3F, 0xFF, 0x14, 0x5C, 0x03, 0x5F, 0xC1,
        0x0B, 0x53, 0x0D, 0x70, 0x06, 0xB1, 0xB2, 0xB3, 0xB4,
        0xB5, 0xB6, 0x71, 0x01, 0x00, 0xFE, 0x00,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(putCertificate, sizeof(putCertificate),
                                        false, response.data(),
                                        response.size(), responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(putCertificate, sizeof(putCertificate),
                                        true, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_HEX16(0x9000, static_cast<uint16_t>(response[0] << 8 |
                                                          response[1]));

    constexpr uint8_t getKeyManagement[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x0B, 0x00,
    };
    applet.transceive(getKeyManagement, sizeof(getKeyManagement), false,
                      response.data(), response.size(), responseLength);
    constexpr uint8_t expected[] = {0x53, 0x0D, 0x70, 0x06, 0xB1, 0xB2,
                                    0xB3, 0xB4, 0xB5, 0xB6, 0x71, 0x01,
                                    0x00, 0xFE, 0x00, 0x90, 0x00};
    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(),
                                  sizeof(expected));

    // The authentication certificate is a different object and is untouched.
    constexpr uint8_t getAuthentication[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00,
    };
    applet.transceive(getAuthentication, sizeof(getAuthentication), false,
                      response.data(), response.size(), responseLength);
    TEST_ASSERT_EQUAL_HEX8(0x53, response[0]);
    TEST_ASSERT_EQUAL_HEX8(0x82, response[1]);
}

// The key and digest of RFC 6979 A.2.5, the ones the board's power-up
// self-test signs with.
constexpr uint8_t kRfc6979Scalar[32] = {
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21,
    0x57, 0x67, 0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8,
    0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
};
constexpr uint8_t kSampleDigest[32] = {
    0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1,
    0xD6, 0x94, 0xF4, 0x1F, 0xC7, 0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9,
    0x89, 0x15, 0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF,
};
// The order of the P-256 group.
constexpr uint8_t kGroupOrder[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
    0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

// Z, then x, then h, with Z and x each padded so the secret scalar starts its
// own SHA-256 block. tools/hedged_ecdsa_reference.py prints the same bytes.
void test_hedged_nonce_seed_follows_the_reference_layout() {
    uint8_t randomness[32];
    for (size_t index = 0; index < sizeof(randomness); ++index) {
        randomness[index] = static_cast<uint8_t>(index);
    }
    uint8_t seed[deskid::kHedgedNonceSeedSize];
    std::memset(seed, 0xEE, sizeof(seed));
    deskid::hedgedNonceSeed(randomness, kRfc6979Scalar, kSampleDigest, seed);

    constexpr uint8_t zeros[63] = {};
    TEST_ASSERT_EQUAL_UINT32(191, sizeof(seed));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(randomness, seed, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zeros, seed + 32, 63);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kRfc6979Scalar, seed + 95, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zeros, seed + 127, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSampleDigest, seed + 159, 32);
}

// RFC 6979 feeds the generator bits2octets(h), the digest reduced below the
// group order. One digest in four billion needs it, so it gets its own test.
void test_hedged_nonce_seed_reduces_a_digest_at_or_above_the_group_order() {
    constexpr uint8_t randomness[32] = {};
    uint8_t seed[deskid::kHedgedNonceSeedSize];
    uint8_t expected[32] = {};

    deskid::hedgedNonceSeed(randomness, kRfc6979Scalar, kGroupOrder, seed);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, seed + 159, 32);

    // Order + 0x1AF: the addition carries out of the last byte, so the
    // subtraction has to borrow back through it.
    uint8_t above[32];
    std::memcpy(above, kGroupOrder, sizeof(above));
    above[31] = 0x00;
    above[30] = 0x27;
    expected[31] = 0xAF;
    expected[30] = 0x01;
    deskid::hedgedNonceSeed(randomness, kRfc6979Scalar, above, seed);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, seed + 159, 32);

    uint8_t below[32];
    std::memcpy(below, kGroupOrder, sizeof(below));
    below[31] = 0x50;
    deskid::hedgedNonceSeed(randomness, kRfc6979Scalar, below, seed);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(below, seed + 159, 32);
}

// A board whose signing self-test failed says so in the status object, where
// a host can read it without a fingerprint.
void test_status_object_reports_a_failed_signing_self_test() {
    selectApplet();
    diagnostics.signingSelfTestPassed = false;
    constexpr uint8_t getStatus[] = {
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x00,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(getStatus, sizeof(getStatus), false,
                                        response.data(), response.size(),
                                        responseLength));
    constexpr uint8_t tail[] = {0x15, 0x01, 0x00, 0xFE, 0x00, 0x90, 0x00};
    TEST_ASSERT_GREATER_THAN_UINT32(sizeof(tail), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(
        tail, response.data() + responseLength - sizeof(tail), sizeof(tail));
}

void test_autotype_fires_once_per_arming_and_only_inside_the_window() {
    deskid::Autotype autotype;
    // A touch the host did not ask to have typed types nothing.
    TEST_ASSERT_FALSE(autotype.take(1000));

    autotype.arm(10, 1000);
    TEST_ASSERT_EQUAL_UINT8(10, autotype.secondsRemaining(1000));
    TEST_ASSERT_EQUAL_UINT8(1, autotype.secondsRemaining(10999));
    TEST_ASSERT_TRUE(autotype.take(10999));
    // One arming is one emission: a second touch needs a second arming.
    TEST_ASSERT_FALSE(autotype.take(10999));
    TEST_ASSERT_EQUAL_UINT8(0, autotype.secondsRemaining(10999));

    autotype.arm(10, 20000);
    TEST_ASSERT_FALSE(autotype.take(30000));
    TEST_ASSERT_EQUAL_UINT32(1, autotype.emissions());

    // A host cannot hold the board armed, and zero seconds disarms it.
    autotype.arm(255, 40000);
    TEST_ASSERT_EQUAL_UINT8(deskid::kMaximumAutotypeSeconds,
                            autotype.secondsRemaining(40000));
    autotype.arm(0, 41000);
    TEST_ASSERT_FALSE(autotype.take(41000));
    TEST_ASSERT_EQUAL_UINT32(1, autotype.emissions());
}

void test_autotype_to_wake_taps_first_and_types_when_the_host_says_lit() {
    deskid::Autotype autotype;
    autotype.arm(10, 1000, true);
    TEST_ASSERT_TRUE(autotype.take(2000));
    // The caller taps the wake key. No digits yet, so no emission yet.
    TEST_ASSERT_TRUE(autotype.wakes());
    TEST_ASSERT_EQUAL_UINT32(0, autotype.emissions());

    // The display is still dark and the host renews: the match keeps waiting.
    TEST_ASSERT_FALSE(autotype.arm(10, 2500, true));
    // The host sees the lock screen lit: this arming is the word to type,
    // and it is spent on that.
    TEST_ASSERT_TRUE(autotype.arm(10, 3000));
    TEST_ASSERT_EQUAL_UINT32(1, autotype.emissions());
    TEST_ASSERT_FALSE(autotype.take(3500));
    // The word is given once. A second arming types nothing more.
    TEST_ASSERT_FALSE(autotype.arm(10, 3600));
    TEST_ASSERT_EQUAL_UINT32(1, autotype.emissions());
}

void test_autotype_types_again_until_the_host_acts() {
    deskid::Autotype autotype;
    autotype.arm(10, 1000, true);
    TEST_ASSERT_TRUE(autotype.take(2000));
    // Nothing is typed again before the host's word.
    TEST_ASSERT_FALSE(autotype.retype(2000 + deskid::kRetypeMilliseconds));
    TEST_ASSERT_TRUE(autotype.arm(10, 3000));

    // The display was still coming up and macOS dropped the digits.
    TEST_ASSERT_FALSE(autotype.retype(3000 + deskid::kRetypeMilliseconds - 1));
    TEST_ASSERT_TRUE(autotype.retype(3000 + deskid::kRetypeMilliseconds));
    TEST_ASSERT_EQUAL_UINT32(2, autotype.emissions());
    // These landed: macOS asked the card to sign. Nothing more is typed.
    autotype.hostActed();
    TEST_ASSERT_FALSE(autotype.retype(60000));
    TEST_ASSERT_EQUAL_UINT32(2, autotype.emissions());
}

void test_autotype_stops_typing_into_a_mac_that_never_answers() {
    deskid::Autotype autotype;
    autotype.wokeHost(1000);
    TEST_ASSERT_TRUE(autotype.arm(10, 2000));
    uint64_t now = 2000;
    uint32_t retypes = 0;
    for (int tick = 0; tick < 200; ++tick) {
        now += 100;
        if (autotype.retype(now)) {
            ++retypes;
        }
    }
    // An unpaired Mac takes the digits as a wrong password, so this is
    // bounded, and it ends with the woken match at the latest.
    TEST_ASSERT_TRUE(retypes <= deskid::kMaximumRetypes);
    TEST_ASSERT_EQUAL_UINT32(1 + retypes, autotype.emissions());

    // A host that disarms stops it at once.
    autotype.wokeHost(50000);
    TEST_ASSERT_TRUE(autotype.arm(10, 51000));
    autotype.arm(0, 51500);
    TEST_ASSERT_FALSE(autotype.retype(51000 + deskid::kRetypeMilliseconds));
}

void test_autotype_forgets_a_woken_match_nobody_claimed() {
    deskid::Autotype autotype;
    // Something else unlocked the Mac after the wake tap: the host disarms.
    autotype.arm(10, 1000, true);
    TEST_ASSERT_TRUE(autotype.take(2000));
    autotype.arm(0, 2500);
    TEST_ASSERT_FALSE(autotype.arm(10, 3000));
    TEST_ASSERT_TRUE(autotype.take(3500));
    TEST_ASSERT_EQUAL_UINT32(1, autotype.emissions());

    // The host said nothing in time: the touch is not typed for.
    autotype.arm(10, 10000, true);
    TEST_ASSERT_TRUE(autotype.take(11000));
    TEST_ASSERT_FALSE(
        autotype.arm(10, 11000 + deskid::kWokenMatchMilliseconds));
    TEST_ASSERT_EQUAL_UINT32(1, autotype.emissions());
}

void test_autotype_types_for_a_match_that_woke_a_sleeping_host() {
    deskid::Autotype autotype;
    // Nobody armed the board: the host was asleep. The match woke it.
    autotype.wokeHost(1000);
    TEST_ASSERT_EQUAL_UINT32(0, autotype.emissions());
    // The host is up, sees a lit lock screen and arms: that is the word.
    TEST_ASSERT_TRUE(autotype.arm(10, 4000));
    TEST_ASSERT_EQUAL_UINT32(1, autotype.emissions());

    // A Mac that woke unlocked never arms, and the match lapses.
    autotype.wokeHost(20000);
    TEST_ASSERT_FALSE(
        autotype.arm(10, 20000 + deskid::kWokenMatchMilliseconds));
    // One that disarms drops it at once.
    autotype.wokeHost(40000);
    autotype.arm(0, 41000);
    TEST_ASSERT_FALSE(autotype.arm(10, 42000));
}

void test_autotype_wake_tap_is_left_shift_alone() {
    uint8_t report[8];
    std::memset(report, 0xAA, sizeof(report));
    deskid::Autotype::wakeReport(true, report);
    TEST_ASSERT_EQUAL_UINT8(0x02, report[0]);
    for (size_t slot = 1; slot < sizeof(report); ++slot) {
        TEST_ASSERT_EQUAL_UINT8(0, report[slot]);
    }
    std::memset(report, 0xAA, sizeof(report));
    deskid::Autotype::wakeReport(false, report);
    for (size_t slot = 0; slot < sizeof(report); ++slot) {
        TEST_ASSERT_EQUAL_UINT8(0, report[slot]);
    }
}

void test_autotype_presses_return_and_types_nothing_else() {
    // One key: its press and its release.
    TEST_ASSERT_EQUAL_UINT32(2, deskid::Autotype::kReportCount);

    uint8_t report[8];
    std::memset(report, 0xAA, sizeof(report));
    deskid::Autotype::report(0, report);
    // Return alone: no modifier, no digit. A digit would draw a dot in the
    // PIN field, and the field is submitted empty.
    const uint8_t pressed[8] = {0, 0, 0x28, 0, 0, 0, 0, 0};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pressed, report, sizeof(report));

    // The press is followed by a release: a key left down repeats until
    // something else is typed.
    std::memset(report, 0xAA, sizeof(report));
    deskid::Autotype::report(1, report);
    const uint8_t released[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(released, report, sizeof(report));
}

void test_wake_line_is_believed_after_both_levels_and_reads_its_touched_level() {
    // The R503 holds WAKEUP high and drives it low for as long as a finger
    // is on the ring.
    deskid::WakeLine line(false);
    line.observe(true);
    TEST_ASSERT_FALSE(line.usable());
    // A level that has never changed says nothing: it reads the same on a
    // wire that was never soldered.
    TEST_ASSERT_FALSE(line.touched(false));
    line.observe(false);
    TEST_ASSERT_TRUE(line.usable());
    TEST_ASSERT_TRUE(line.touched(false));
    // Resting high is an empty ring. Reading it as a finger is the fault
    // this class was written after.
    TEST_ASSERT_FALSE(line.touched(true));

    deskid::WakeLine activeHigh(true);
    activeHigh.observe(false);
    activeHigh.observe(true);
    TEST_ASSERT_TRUE(activeHigh.touched(true));
    TEST_ASSERT_FALSE(activeHigh.touched(false));
}

void test_one_match_opens_an_enrollment_session_for_one_finger() {
    selectApplet();
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    auto step = [&](bool userPresent) {
        return applet.transceive(enroll, sizeof(enroll), userPresent,
                                 response.data(), response.size(),
                                 responseLength);
    };
    diagnostics.nowMilliseconds = 1000;
    diagnostics.enrollStage = 0;
    const size_t before = diagnostics.enrollRequests;

    // An enrolled finger vouches for the new one, once.
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      step(false));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete, step(true));
    TEST_ASSERT_TRUE(applet.enrollmentOpen());

    // Inside the session a step needs no match, so the finger on the ring
    // can be one the sensor has never seen.
    diagnostics.nowMilliseconds = 2000;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete, step(false));
    TEST_ASSERT_EQUAL_UINT32(before + 2, diagnostics.enrollRequests);

    // A finger is recorded as several placements. Storing one keeps the
    // session open, with a fresh window to place the next.
    diagnostics.enrollStage = 3;
    for (uint8_t stored = 1; stored < deskid::kEnrollmentSessionTemplates;
         ++stored) {
        TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete, step(false));
        TEST_ASSERT_TRUE(applet.enrollmentOpen());
        diagnostics.nowMilliseconds +=
            deskid::kEnrollmentSessionMilliseconds - 1;
    }
    // The last placement the match pays for ends it.
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete, step(false));
    TEST_ASSERT_FALSE(applet.enrollmentOpen());
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      step(false));
}

// Whoever stores the first template on an empty library was asked for no
// match, and is the same person a few seconds later: the rest of that finger
// needs none either.
void test_the_first_template_opens_the_session_for_the_rest_of_the_finger() {
    selectApplet();
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    diagnostics.nowMilliseconds = 1000;
    diagnostics.enrolledTemplates = 0;
    diagnostics.enrollStage = 3;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(enroll, sizeof(enroll), false,
                                        response.data(), response.size(),
                                        responseLength));
    diagnostics.enrolledTemplates = 1;
    TEST_ASSERT_TRUE(applet.enrollmentOpen());
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(enroll, sizeof(enroll), false,
                                        response.data(), response.size(),
                                        responseLength));
}

void test_enrollment_session_expires_and_ends_with_the_card_session() {
    selectApplet();
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    auto step = [&](bool userPresent) {
        return applet.transceive(enroll, sizeof(enroll), userPresent,
                                 response.data(), response.size(),
                                 responseLength);
    };
    diagnostics.nowMilliseconds = 1000;
    diagnostics.enrollStage = 1;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete, step(true));
    diagnostics.nowMilliseconds =
        1000 + deskid::kEnrollmentSessionMilliseconds - 1;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete, step(false));
    // A session nobody finished must not wait for whoever touches next.
    diagnostics.nowMilliseconds = 1000 + deskid::kEnrollmentSessionMilliseconds;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      step(false));

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete, step(true));
    applet.reset();
    selectApplet();
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      step(false));
}

void test_a_declined_enrollment_opens_no_session() {
    selectApplet();
    diagnostics.enrollSupported = false;
    diagnostics.nowMilliseconds = 1000;
    constexpr uint8_t enroll[] = {0x80, 0xE1, 0x00, 0x00, 0x00};
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(enroll, sizeof(enroll), true,
                                        response.data(), response.size(),
                                        responseLength));
    diagnostics.enrollSupported = true;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(enroll, sizeof(enroll), false,
                                        response.data(), response.size(),
                                        responseLength));
}

// 80 E4 <class> 00 20 <number> 00: what a PAM module sends when sudo asks.
std::array<uint8_t, 38> approvalRequest(uint8_t requestClass = 0x01) {
    std::array<uint8_t, 38> request = {0x80, 0xE4, requestClass, 0x00, 0x20};
    for (size_t index = 0; index < 32; ++index) {
        request[5 + index] = static_cast<uint8_t>(0xC0 + index);
    }
    return request;
}

void test_an_approval_waits_for_a_touch_and_signs_the_labelled_request() {
    selectApplet();
    const auto request = approvalRequest();
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(request.data(), request.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(0, responseLength);
    TEST_ASSERT_EQUAL_UINT32(0, credential.signedMessageLength);

    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(request.data(), request.size(), true,
                                        response.data(), response.size(),
                                        responseLength));
    constexpr uint8_t expected[] = {0x30, 0x06, 0x02, 0x01, 0x03,
                                    0x02, 0x01, 0x04, 0x90, 0x00};
    TEST_ASSERT_EQUAL_UINT32(sizeof(expected), responseLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, response.data(), sizeof(expected));

    // The card hashes the label, a zero, the class and the number itself. A
    // host that could hand this path a digest could have it sign a login.
    std::array<uint8_t, 47> message{};
    std::memcpy(message.data(), "DeskID PAM v1", 13);
    message[14] = 0x01;
    std::memcpy(message.data() + 15, request.data() + 5, 32);
    TEST_ASSERT_EQUAL_UINT32(message.size(), credential.signedMessageLength);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(message.data(),
                                  credential.signedMessage.data(),
                                  message.size());
}

void test_an_approval_is_never_paid_for_in_advance() {
    selectApplet();
    // A PIN answered by a touch unlocks the next login signature.
    constexpr uint8_t verify[] = {
        0x00, 0x20, 0x00, 0x80, 0x08, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(verify, sizeof(verify), true,
                                        response.data(), response.size(),
                                        responseLength));
    // It unlocks no approval.
    const auto request = approvalRequest();
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(request.data(), request.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL_UINT32(0, credential.signedMessageLength);

    // Nor does a touch the idle ring took before anyone asked.
    deskid::EarlyTouch touch(30000);
    touch.record(1000);
    TEST_ASSERT_FALSE(deskid::EarlyTouch::maySpend(0xE4));
    TEST_ASSERT_FALSE(touch.spend(0xE4, 2000));
    TEST_ASSERT_TRUE(touch.held(2000));
}

void test_an_approval_buys_nothing_else() {
    selectApplet();
    const auto request = approvalRequest();
    size_t responseLength = 0;
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                      applet.transceive(request.data(), request.size(), true,
                                        response.data(), response.size(),
                                        responseLength));

    // No login signature, no key agreement and no second approval.
    std::array<uint8_t, 44> authenticate = {
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    };
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(authenticate.data(), authenticate.size(),
                                        false, response.data(), response.size(),
                                        responseLength));
    const auto agreement = keyAgreementRequest();
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(agreement.data(), agreement.size(),
                                        false, response.data(), response.size(),
                                        responseLength));
    TEST_ASSERT_EQUAL(deskid::TransceiveStatus::userPresenceRequired,
                      applet.transceive(request.data(), request.size(), false,
                                        response.data(), response.size(),
                                        responseLength));
}

void test_an_approval_refuses_what_it_cannot_sign_without_waiting() {
    selectApplet();
    size_t responseLength = 0;
    auto expectStatus = [&](const uint8_t *apdu, size_t length,
                            uint16_t expected) {
        TEST_ASSERT_EQUAL(deskid::TransceiveStatus::complete,
                          applet.transceive(apdu, length, false,
                                            response.data(), response.size(),
                                            responseLength));
        TEST_ASSERT_EQUAL_UINT32(2, responseLength);
        TEST_ASSERT_EQUAL_HEX16(expected, static_cast<uint16_t>(
                                              response[0] << 8 | response[1]));
    };

    // A class the board has no look for.
    const auto unknownClass = approvalRequest(0x02);
    expectStatus(unknownClass.data(), unknownClass.size(), 0x6A86);
    // A number one byte short.
    auto shortNumber = approvalRequest();
    shortNumber[4] = 0x1F;
    expectStatus(shortNumber.data(), shortNumber.size() - 1, 0x6700);
    // The instruction under the interindustry class.
    auto wrongClass = approvalRequest();
    wrongClass[0] = 0x00;
    expectStatus(wrongClass.data(), wrongClass.size(), 0x6A86);

    // A board with no identity has nothing to sign with, and says so at once.
    credential.forget();
    const auto request = approvalRequest();
    expectStatus(request.data(), request.size(), 0x6A88);
    TEST_ASSERT_EQUAL_UINT32(0, credential.signedMessageLength);
}

void test_a_touch_is_fresh_only_after_the_ring_was_seen_empty() {
    deskid::FreshTouch touch(3);
    // A finger that was resting there when the request came.
    TEST_ASSERT_FALSE(touch.observe(true));
    TEST_ASSERT_FALSE(touch.observe(true));
    // One empty reading can be a capture that failed under that finger.
    TEST_ASSERT_FALSE(touch.observe(false));
    TEST_ASSERT_FALSE(touch.observe(true));
    TEST_ASSERT_FALSE(touch.observe(false));
    TEST_ASSERT_FALSE(touch.observe(false));
    TEST_ASSERT_FALSE(touch.observe(true));

    // Lifted for three readings in a row, then placed.
    TEST_ASSERT_FALSE(touch.observe(false));
    TEST_ASSERT_FALSE(touch.observe(false));
    TEST_ASSERT_FALSE(touch.observe(false));
    TEST_ASSERT_TRUE(touch.observe(true));
    TEST_ASSERT_TRUE(touch.observe(true));
    // A rejected finger that lifts and tries again is still fresh.
    TEST_ASSERT_FALSE(touch.observe(false));
    TEST_ASSERT_TRUE(touch.observe(true));
}

void test_only_an_approval_demands_a_fresh_touch() {
    TEST_ASSERT_TRUE(deskid::demandsFreshTouch(0xE4));
    // The rest keep the gate they had: a finger already on the ring counts.
    TEST_ASSERT_FALSE(deskid::demandsFreshTouch(0x20));
    TEST_ASSERT_FALSE(deskid::demandsFreshTouch(0x87));
    TEST_ASSERT_FALSE(deskid::demandsFreshTouch(0xE1));
}

void test_the_idle_ring_listens_only_for_an_armed_host_or_a_sleeping_one() {
    // Nobody asked: a match now would wait for whichever process asks first.
    TEST_ASSERT_FALSE(deskid::idleRingListens(0, false));
    // The helper said a PIN field has the keyboard, or the display is dark.
    TEST_ASSERT_TRUE(deskid::idleRingListens(1, false));
    // A sleeping Mac runs no helper, and the touch is what wakes it.
    TEST_ASSERT_TRUE(deskid::idleRingListens(0, true));
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_selects_standard_piv_aid);
    RUN_TEST(test_certificate_response_is_chained_without_truncation);
    RUN_TEST(test_public_card_objects_include_device_identifier);
    RUN_TEST(test_general_authenticate_waits_for_user_presence);
    RUN_TEST(test_verify_authorizes_exactly_one_signature);
    RUN_TEST(test_verify_status_query_does_not_request_a_fingerprint);
    RUN_TEST(test_rejects_malformed_authentication_template);
    RUN_TEST(test_generate_key_pair_is_gated_and_returns_public_point);
    RUN_TEST(test_generate_key_pair_rejects_non_p256_algorithm);
    RUN_TEST(test_put_data_is_gated_and_replaces_certificate);
    RUN_TEST(test_put_data_rejects_unknown_object);
    RUN_TEST(test_unprovisioned_board_serves_no_public_objects);
    RUN_TEST(test_unprovisioned_board_provisions_without_a_fingerprint);
    RUN_TEST(test_unprovisioned_board_refuses_to_sign_without_waiting);
    RUN_TEST(test_rate_limiter_locks_backs_off_and_resets);
    RUN_TEST(test_lockout_survives_a_power_cycle);
    RUN_TEST(test_piv_aid_is_refused_unless_allowed);
    RUN_TEST(test_status_object_reports_device_state_without_user_presence);
    RUN_TEST(test_download_mode_is_gated_by_user_presence);
    RUN_TEST(test_download_mode_declined_reports_unsupported_instruction);
    RUN_TEST(test_enrollment_is_open_while_the_sensor_library_is_empty);
    RUN_TEST(test_enrollment_requires_a_match_once_a_finger_is_enrolled);
    RUN_TEST(test_enrollment_declined_reports_unsupported_instruction);
    RUN_TEST(test_forgetting_fingerprints_requires_a_match);
    RUN_TEST(test_forgetting_an_empty_library_needs_no_match);
    RUN_TEST(test_forgetting_declined_reports_unsupported_instruction);
    RUN_TEST(test_arm_ring_needs_no_fingerprint_and_takes_a_duration);
    RUN_TEST(test_selecting_the_applet_arms_the_ring);
    RUN_TEST(test_early_touch_answers_only_the_login_instructions);
    RUN_TEST(test_early_touch_is_single_use_and_expires);
    RUN_TEST(test_attempt_is_charged_before_the_verdict_and_survives_power_loss);
    RUN_TEST(test_a_match_clears_the_charge_and_says_so_on_disk);
    RUN_TEST(test_one_touch_is_one_charge_for_at_most_three_verdicts);
    RUN_TEST(test_a_touch_stops_riding_once_locked_out_and_a_match_starts_over);
    RUN_TEST(test_an_attempt_that_cannot_be_written_down_is_refused);
    RUN_TEST(test_enrollment_is_gated_while_the_template_count_is_unknown);
    RUN_TEST(test_verify_expires_instead_of_waiting_for_a_signature);
    RUN_TEST(test_status_object_fits_the_longest_version_string);
    RUN_TEST(test_key_agreement_waits_for_a_fingerprint_and_returns_the_secret);
    RUN_TEST(test_one_touch_buys_one_signature_and_one_key_agreement);
    RUN_TEST(test_a_touch_spent_on_a_signature_covers_the_key_agreement_after_it);
    RUN_TEST(test_the_key_agreement_a_touch_bought_expires_with_it);
    RUN_TEST(test_key_agreement_rejects_malformed_templates_without_waiting);
    RUN_TEST(test_key_agreement_is_refused_without_a_key_management_identity);
    RUN_TEST(test_key_management_slot_generates_its_own_key_behind_the_gate);
    RUN_TEST(test_key_management_certificate_has_its_own_object);
    RUN_TEST(test_hedged_nonce_seed_follows_the_reference_layout);
    RUN_TEST(test_hedged_nonce_seed_reduces_a_digest_at_or_above_the_group_order);
    RUN_TEST(test_status_object_reports_a_failed_signing_self_test);
    RUN_TEST(test_autotype_fires_once_per_arming_and_only_inside_the_window);
    RUN_TEST(test_autotype_to_wake_taps_first_and_types_when_the_host_says_lit);
    RUN_TEST(test_autotype_types_again_until_the_host_acts);
    RUN_TEST(test_autotype_stops_typing_into_a_mac_that_never_answers);
    RUN_TEST(test_autotype_forgets_a_woken_match_nobody_claimed);
    RUN_TEST(test_autotype_types_for_a_match_that_woke_a_sleeping_host);
    RUN_TEST(test_autotype_wake_tap_is_left_shift_alone);
    RUN_TEST(test_autotype_presses_return_and_types_nothing_else);
    RUN_TEST(test_wake_line_is_believed_after_both_levels_and_reads_its_touched_level);
    RUN_TEST(test_one_match_opens_an_enrollment_session_for_one_finger);
    RUN_TEST(test_the_first_template_opens_the_session_for_the_rest_of_the_finger);
    RUN_TEST(test_enrollment_session_expires_and_ends_with_the_card_session);
    RUN_TEST(test_a_declined_enrollment_opens_no_session);
    RUN_TEST(test_an_approval_waits_for_a_touch_and_signs_the_labelled_request);
    RUN_TEST(test_an_approval_is_never_paid_for_in_advance);
    RUN_TEST(test_an_approval_buys_nothing_else);
    RUN_TEST(test_an_approval_refuses_what_it_cannot_sign_without_waiting);
    RUN_TEST(test_a_touch_is_fresh_only_after_the_ring_was_seen_empty);
    RUN_TEST(test_only_an_approval_demands_a_fresh_touch);
    RUN_TEST(test_the_idle_ring_listens_only_for_an_armed_host_or_a_sleeping_one);
    return UNITY_END();
}