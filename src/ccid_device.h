// Copyright (c) 2026 Maksym Bardakh. All rights reserved.
// SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
// Source-available under LICENSE.md with the permissions in LICENSING.md.

#pragma once

#include <cstddef>
#include <cstdint>

#include "esp_err.h"

namespace deskid {

struct CcidRequest {
    static constexpr size_t kMaximumApduLength = 2038;

    uint8_t slot = 0;
    uint8_t sequence = 0;
    uint32_t powerEpoch = 0;
    size_t apduLength = 0;
    uint8_t apdu[kMaximumApduLength]{};
};

esp_err_t installCcidDevice();
bool waitForCcidRequest(CcidRequest &request, uint32_t timeoutMilliseconds);
bool sendCcidResponse(const CcidRequest &request, const uint8_t *response,
                      size_t responseLength);
bool sendCcidTimeExtension(const CcidRequest &request, uint8_t multiplier = 1);
bool ccidRequestWasAborted(const CcidRequest &request);
uint32_t ccidPowerEpoch();
uint32_t ccidSecureRequests();

// The HID side of the same USB device: a keyboard the board types the PIN
// digits on, and a vendor interface a host arms that typing through. See
// deskid::Autotype for the policy; these only move bytes.

/// True when a host has sent an arming request since the last call. The USB
/// task receives it and the main task acts on it.
bool takeAutotypeArm(uint8_t &seconds, bool &toWake);
/// What the arming interface answers when a host reads it back.
/// `watchesForFree` is the wake line being trusted: a host may then keep the
/// board armed for as long as it likes, because watching costs no captures.
void publishAutotypeStatus(uint8_t secondsRemaining, uint32_t emissions,
                           bool watchesForFree);
/// Sends one eight-byte keyboard report. False when the host is not taking
/// them: suspended, not configured, or the interface refused.
bool sendKeyboardReport(const uint8_t report[8]);

}  // namespace deskid