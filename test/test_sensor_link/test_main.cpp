#include <unity.h>
#include <array>
#include <cstring>
#include <set>
#include <vector>
#include "sensor_link.h"

using namespace deskid::fpc;

namespace {

// Accepts a frame when the first GCM tag byte is 0xA5 and "decrypts" by copy.
class FakeAead final : public Aead {
public:
    bool open(const uint8_t *, size_t, const uint8_t *, const uint8_t *gcmTag,
              const uint8_t *ciphertext, size_t length,
              uint8_t *plaintext) override {
        ++calls;
        if (gcmTag[0] != 0xA5) {
            return false;
        }
        std::memcpy(plaintext, ciphertext, length);
        return true;
    }
    int calls = 0;
};

class FakeLink final : public LinkState {
public:
    bool keyed() const override { return isKeyed; }
    bool isKeyed = true;
};

class FakeTags final : public TagSource {
public:
    uint16_t next() override { return nextTag++; }
    uint16_t nextTag = 0x1234;
};

class FakeAllowList final : public TemplateAllowList {
public:
    bool allowed(uint16_t id) const override { return ids.count(id) != 0; }
    std::set<uint16_t> ids{7};
};

class FakeJournal final : public IvJournal {
public:
    bool seen(const uint8_t *iv) const override {
        return ivs.count(std::vector<uint8_t>(iv, iv + kIvSize)) != 0;
    }
    bool record(const uint8_t *iv) override {
        if (!healthy) {
            return false;
        }
        ivs.insert(std::vector<uint8_t>(iv, iv + kIvSize));
        return true;
    }
    std::set<std::vector<uint8_t>> ivs;
    bool healthy = true;
};

FakeAead aead;
FakeLink linkState;
FakeTags tags;
FakeAllowList allowList;
FakeJournal journal;

void put16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(value & 0xFF);
    out.push_back(value >> 8);
}

std::vector<uint8_t> identifyPayload(uint16_t match, uint16_t templateId,
                                     uint16_t tag) {
    std::vector<uint8_t> p;
    put16(p, kCmdIdentify);
    put16(p, kTypeEvent);
    put16(p, match);
    put16(p, kIdTypeSpecified);
    put16(p, templateId);
    put16(p, tag);
    return p;
}

std::vector<uint8_t> commandPayload(uint16_t command) {
    std::vector<uint8_t> p;
    put16(p, command);
    put16(p, kTypeResponse);
    return p;
}

std::vector<uint8_t> plainFrame(const std::vector<uint8_t> &payload,
                                uint16_t flags = kFlagSenderApp) {
    std::vector<uint8_t> f;
    put16(f, kProtocolVersion);
    put16(f, kTypeEvent);
    put16(f, flags);
    put16(f, static_cast<uint16_t>(payload.size()));
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

std::vector<uint8_t> secureFrame(const std::vector<uint8_t> &payload,
                                 uint8_t ivSeed, bool valid = true) {
    std::vector<uint8_t> body(kIvSize, ivSeed);
    std::vector<uint8_t> gcmTag(kGcmTagSize, valid ? 0xA5 : 0x00);
    body.insert(body.end(), gcmTag.begin(), gcmTag.end());
    body.insert(body.end(), payload.begin(), payload.end());
    return plainFrame(body, kFlagSecure | kFlagSenderApp);
}

Verdict feed(SensorLinkGate &gate, const std::vector<uint8_t> &frame) {
    return gate.onFrame(frame.data(), frame.size());
}

SensorLinkGate makeGate() {
    return SensorLinkGate(linkState, aead, tags, allowList, journal);
}

}  // namespace

void setUp() {
    aead = FakeAead();
    linkState = FakeLink();
    tags = FakeTags();
    allowList = FakeAllowList();
    journal = FakeJournal();
}

void tearDown() {}

void test_rejects_short_wrong_version_and_mis_sized_frames() {
    SensorLinkGate gate = makeGate();
    const uint8_t tiny[4] = {4, 0, 0x13, 0};
    TEST_ASSERT_EQUAL(Reason::Malformed, gate.onFrame(tiny, sizeof tiny).reason);

    std::vector<uint8_t> wrongVersion = plainFrame(commandPayload(kCmdStatus));
    wrongVersion[0] = 3;
    TEST_ASSERT_EQUAL(Reason::Malformed, feed(gate, wrongVersion).reason);

    std::vector<uint8_t> oversized = plainFrame(commandPayload(kCmdStatus));
    oversized[6] = 0xFF;
    oversized[7] = 0xFF;
    TEST_ASSERT_EQUAL(Reason::Malformed, feed(gate, oversized).reason);
}

void test_keyed_link_rejects_plaintext_match() {
    SensorLinkGate gate = makeGate();
    const uint16_t tag = gate.beginIdentify();
    const Verdict v =
        feed(gate, plainFrame(identifyPayload(kIdentifyMatch, 7, tag)));
    TEST_ASSERT_EQUAL(Outcome::Rejected, v.outcome);
    TEST_ASSERT_EQUAL(Reason::Plaintext, v.reason);
}

void test_keyed_link_passes_plaintext_status_as_diagnostic_only() {
    SensorLinkGate gate = makeGate();
    for (uint16_t command : {kCmdStatus, kCmdVersion, kCmdGetSystemConfig}) {
        TEST_ASSERT_EQUAL(Outcome::Diagnostic,
                          feed(gate, plainFrame(commandPayload(command))).outcome);
    }
}

void test_rejects_frames_claiming_the_host_as_sender() {
    SensorLinkGate gate = makeGate();
    const uint16_t tag = gate.beginIdentify();
    std::vector<uint8_t> frame =
        secureFrame(identifyPayload(kIdentifyMatch, 7, tag), 1);
    frame[4] = static_cast<uint8_t>(kFlagSecure | kFlagSenderHost);
    TEST_ASSERT_EQUAL(Reason::Reflected, feed(gate, frame).reason);
}

void test_rejects_short_secure_frame_without_calling_aead() {
    SensorLinkGate gate = makeGate();
    std::vector<uint8_t> body(kIvSize + kGcmTagSize, 0xA5);
    TEST_ASSERT_EQUAL(Reason::Malformed,
                      feed(gate, plainFrame(body, kFlagSecure | kFlagSenderApp)).reason);
    TEST_ASSERT_EQUAL(0, aead.calls);
}

void test_rejects_forged_secure_frame() {
    SensorLinkGate gate = makeGate();
    const uint16_t tag = gate.beginIdentify();
    TEST_ASSERT_EQUAL(Reason::Forged,
                      feed(gate, secureFrame(identifyPayload(kIdentifyMatch, 7, tag), 1, false)).reason);
}

void test_rejects_replayed_iv() {
    SensorLinkGate gate = makeGate();
    const uint16_t tag = gate.beginIdentify();
    const std::vector<uint8_t> frame =
        secureFrame(identifyPayload(kIdentifyMatch, 7, tag), 1);
    TEST_ASSERT_EQUAL(Outcome::Match, feed(gate, frame).outcome);
    gate.beginIdentify();
    TEST_ASSERT_EQUAL(Reason::Replayed, feed(gate, frame).reason);
}

void test_identify_needs_a_pending_request_and_its_tag() {
    SensorLinkGate gate = makeGate();
    TEST_ASSERT_EQUAL(Reason::Unsolicited,
                      feed(gate, secureFrame(identifyPayload(kIdentifyMatch, 7, 0x1234), 1)).reason);

    const uint16_t tag = gate.beginIdentify();
    TEST_ASSERT_EQUAL(Reason::ForeignTag,
                      feed(gate, secureFrame(identifyPayload(kIdentifyMatch, 7, tag + 1), 2)).reason);

    const uint16_t second = gate.beginIdentify();
    TEST_ASSERT_EQUAL(Outcome::NoMatch,
                      feed(gate, secureFrame(identifyPayload(kIdentifyNoMatch, 0, second), 3)).outcome);
    TEST_ASSERT_EQUAL(Reason::Unsolicited,
                      feed(gate, secureFrame(identifyPayload(kIdentifyMatch, 7, second), 4)).reason);
}

void test_match_needs_an_allowed_template() {
    SensorLinkGate gate = makeGate();
    uint16_t tag = gate.beginIdentify();
    TEST_ASSERT_EQUAL(Reason::UnknownTemplate,
                      feed(gate, secureFrame(identifyPayload(kIdentifyMatch, 9, tag), 1)).reason);

    tag = gate.beginIdentify();
    const Verdict v = feed(gate, secureFrame(identifyPayload(kIdentifyMatch, 7, tag), 2));
    TEST_ASSERT_EQUAL(Outcome::Match, v.outcome);
    TEST_ASSERT_EQUAL_UINT16(7, v.templateId);
}

void test_tag_comes_from_the_tag_source() {
    SensorLinkGate gate = makeGate();
    tags.nextTag = 0xBEEF;
    TEST_ASSERT_EQUAL_UINT16(0xBEEF, gate.beginIdentify());
    TEST_ASSERT_EQUAL_UINT16(0xBEF0, gate.beginIdentify());
}

void test_unrecordable_iv_refuses_the_verdict() {
    SensorLinkGate gate = makeGate();
    journal.healthy = false;
    const uint16_t tag = gate.beginIdentify();
    TEST_ASSERT_EQUAL(Reason::JournalFull,
                      feed(gate, secureFrame(identifyPayload(kIdentifyMatch, 7, tag), 1)).reason);
}

// A bench board has no link key yet, but the tag and template rules still apply.
void test_unkeyed_link_still_binds_tag_and_template() {
    linkState.isKeyed = false;
    SensorLinkGate gate = makeGate();
    uint16_t tag = gate.beginIdentify();
    TEST_ASSERT_EQUAL(Reason::ForeignTag,
                      feed(gate, plainFrame(identifyPayload(kIdentifyMatch, 7, tag + 1))).reason);
    tag = gate.beginIdentify();
    TEST_ASSERT_EQUAL(Outcome::Match,
                      feed(gate, plainFrame(identifyPayload(kIdentifyMatch, 7, tag))).outcome);
}

int main(int, char **) {
    UNITY_BEGIN();
    RUN_TEST(test_rejects_short_wrong_version_and_mis_sized_frames);
    RUN_TEST(test_keyed_link_rejects_plaintext_match);
    RUN_TEST(test_keyed_link_passes_plaintext_status_as_diagnostic_only);
    RUN_TEST(test_rejects_frames_claiming_the_host_as_sender);
    RUN_TEST(test_rejects_short_secure_frame_without_calling_aead);
    RUN_TEST(test_rejects_forged_secure_frame);
    RUN_TEST(test_rejects_replayed_iv);
    RUN_TEST(test_identify_needs_a_pending_request_and_its_tag);
    RUN_TEST(test_match_needs_an_allowed_template);
    RUN_TEST(test_tag_comes_from_the_tag_source);
    RUN_TEST(test_unrecordable_iv_refuses_the_verdict);
    RUN_TEST(test_unkeyed_link_still_binds_tag_and_template);
    return UNITY_END();
}
