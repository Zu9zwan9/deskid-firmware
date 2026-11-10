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

}  // namespace deskid