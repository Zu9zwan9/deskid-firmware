# Third-party notices

The build fetches the components below, and a compiled firmware image contains code from the first five. Each stays under its own license. [LICENSING.md](LICENSING.md) changes none of the rights those licenses give you.

Whoever distributes a firmware image has to pass on the license texts and notices these components require.

## In the firmware image

| Component | Version | License | Source |
|---|---|---|---|
| ESP-IDF | 6.0.1 | Apache-2.0 | https://github.com/espressif/esp-idf |
| Mbed TLS, shipped with ESP-IDF | as shipped | Apache-2.0 OR GPL-2.0-or-later; used here under Apache-2.0 | https://github.com/Mbed-TLS/mbedtls |
| FreeRTOS kernel, shipped with ESP-IDF | as shipped | MIT | https://github.com/FreeRTOS/FreeRTOS-Kernel |
| espressif/esp_tinyusb | 2.1.0 | Apache-2.0 | https://github.com/espressif/esp-usb |
| espressif/tinyusb (TinyUSB, Copyright (c) Ha Thach) | 0.21.0~1 | MIT | https://github.com/hathach/tinyusb |

ESP-IDF bundles further libraries, each under its own license. Espressif lists them in the copyrights page of the ESP-IDF Programming Guide: https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/COPYRIGHT.html

## Build and provisioning tools

These run on the host and are absent from the firmware image.

| Component | Version | License | Source |
|---|---|---|---|
| PlatformIO platform espressif32 | 7.0.1 | Apache-2.0 | https://github.com/platformio/platform-espressif32 |
| cryptography | 48.0.1 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| esp-idf-nvs-partition-gen | 0.3.0 | Apache-2.0 | https://github.com/espressif/esp-idf-nvs-partition-gen |

## Keeping this file true

Versions come from `platformio.ini`, `dependencies.lock`, `src/idf_component.yml` and `tools/requirements-provisioning.txt`. Licenses were read from each project's own license file on 2026-11-13. Check both again whenever one of those four files changes.
