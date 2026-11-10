# DeskID

DeskID is an ESP32-S3 USB CCID device that exposes a minimal PIV application and gates private-key signatures with an R503 fingerprint match.

This repository is a production-oriented firmware baseline, not a claim that an ESP32-S3 plus R503 provides Apple Secure Enclave-level assurance. Read [Security limits](#security-limits) before deploying it.

## What is implemented

- Native ESP-IDF/TinyUSB CCID transport for the ESP32-S3 USB-OTG peripheral.
- Mandatory CCID power, status, parameter, transfer, abort, clock, and data-rate paths.
- PIV application selection, Discovery, CCC, CHUID, certificate object `5FC105`, response chaining, `VERIFY`, and ECC P-256 `GENERAL AUTHENTICATE` for slot `9A`.
- Host-driven authentication: macOS sends an APDU, CCID reports time extensions while the R503 waits, and only a matching fingerprint releases the signature. The device never sends an unsolicited APDU.
- A touch that arrives before the request does still counts. The sensor is scanned between requests and a match is held for 30 s, spendable once, by `VERIFY` or `GENERAL AUTHENTICATE` only — see [Touch first](#touch-first).
- PSA Crypto signing with a P-256 key and a matching X.509 certificate in NVS, provisioned either from a host image or generated on the device itself (`GENERATE ASYMMETRIC KEY PAIR` `0x47` + `PUT DATA` `0xDB`).
- A diagnostic channel over PC/SC: a status object at `GET DATA 5FFF01`, and `80 F0 00 00 00` to reboot into ROM download mode with no BOOT press. Both exist because this board has no serial console. On this board `80 F0` lands in USB-OTG DFU rather than the serial loader — see [Entering download mode](#entering-download-mode).
- R503 packet validation, timeouts, password rotation, security level `3`, the R503 default, and enrollment over the card channel (`80 E1 00 00 00`) because a soldered sensor has no other host.
- Development and production firmware profiles plus host-side APDU tests.

The R503 has red and blue LEDs, not green. DeskID uses breathing blue while a request is
waiting, solid blue the instant skin lands and through the match that follows, and
flashing red on refusal. The ring is dark when nothing is happening — and live anyway:
see [Touch first](#touch-first).

## Hardware

The target is an [ESP32-S3 Super Mini](https://iotcrazy.com/docs/esp32-s3-m.html) board (`ESP32-S3FH4R2`, 4 MB flash, 22.5 × 18 mm) selected in PlatformIO as `lolin_s3_mini`. PSRAM is present but intentionally unused; credentials and USB buffers stay in internal RAM. The board has a WS2812 RGB LED on GPIO 48 (unused by DeskID — the R503 provides its own user-feedback LEDs).

### Fingerprint sensor wiring

The R503 ships with an MX1.0-6P pigtail. Pin 1 is the red wire.

**Go by the printed labels, never by counting pads.** Every pad that matters is labelled.

| R503 pin | Wire | R503 signal | Board pad | GPIO | Direction |
|---|---|---|---|---|---|
| 1 | red | `VIN` 3.3 V | pad marked `3V3` | — | Board to sensor |
| 2 | black | `GND` | pad marked `GND` | — | Ground |
| 3 | yellow | `TXD` | upper unlabelled left pad | `GPIO43` | Sensor to ESP32 |
| 4 | green | `RXD` | lower unlabelled left pad | `GPIO44` | ESP32 to sensor |
| 5 | blue | `WAKEUP` | pad marked `4` | `GPIO4` | Sensor to ESP32, active high |
| 6 | white | `3.3VT` | pad marked `3V3` | — | Touch-sense supply, ~5 µA |

Both edges as printed, USB-C at the top and the module facing you:

```
        left edge                          right edge

   48    RGB LED — leave alone        BAT   battery — leave alone
   ──    ◀── yellow  TXD  GPIO43       5V   never use this
   ──    ──▶ green   RXD  GPIO44      GND   ◀── black  GND
    1                                 3V3   ◀── red VIN + white 3.3VT
    2                                  13
    3                                  12
    4    ◀── blue    WAKEUP  GPIO4     11
    5                                  10
    6                                   9
    7                                   8
```

**The two traps, both of which have cost time on this bench.**

First, each edge starts with a pad that is not part of the numbered row: `48` (the RGB LED) top left and `BAT` top right, tucked beside the USB-C connector. Counting them as "pad 1" shifts every wire by one — yellow onto the LED pad, blue onto `3`, and on the right edge red onto `GND` and black onto `5V`, which is reverse polarity at 5 V and can destroy the sensor. Read the labels instead: blue belongs on the pad marked `4`, and the two UART pads are the only unlabelled ones on that edge, sitting between `48` and `1`.

Second, those two UART pads carry contradictory silkscreens: the front reads `RX` next to both, the back reads `TX` then `RX`, and the vendor [pinout](https://iotcrazy.com/docs/esp32-s3-m.html) shows the upper one is `U0TXD` = `GPIO43` and the lower `U0RXD` = `GPIO44`. Ignore all three. Sensor `TXD` goes to the upper pad and sensor `RXD` to the lower one — and if they end up reversed it does not matter, because `R503Sensor::initialize` retries once with the pins swapped at reduced drive strength.

DeskID runs the sensor on `UART_NUM_1` at 57600 baud, 8N1, no flow control, with `GPIO44` as its transmitter and `GPIO43` as its receiver.

**Solder blue.** `GPIO4` is an input with the internal pull-down enabled and the R503 drives `WAKEUP` high on touch, for about 5 µA. During an authentication it is only a shortcut — `GenImg` already answers `0x02` when the ring is untouched, so `R503Sensor::fingerPresent` falls back to a UART probe and costs one round trip per poll. Between authentications it is the whole mechanism, because [Touch first](#touch-first) needs to watch the ring continuously and `GenImg` is a full image capture, not a probe: it powers the imaging array and the illumination LED. Running it four times a second forever browned the 3V3 rail out badly enough to power-cycle the board and leave the sensor unauthenticated (measured 2026-09-02). So the idle scan watches `WAKEUP` and nothing else.

Leave blue unconnected and the card still enrolls, signs and logs you in exactly as it always did — the ring just stays dark until a request arrives, which is the slow sequence this product exists to remove.

Do not power the sensor from `5V`. `VIN` and `3.3VT` both take 3.3 V, and `3.3VT` must stay powered for finger detection to work at all.

Native USB uses the board USB-C connector (`GPIO19` D- and `GPIO20` D+ internally). UART logging is disabled because `GPIO43`/`GPIO44` belong to the fingerprint sensor.

If the sensor answers on neither orientation the firmware still starts and USB still enumerates; `GET DATA 5FFF01` then reports `sensor: error` and every match fails closed. That is deliberate — a sensor fault that also took USB down would leave no channel to find out why, because this board has no serial console.

Fingerprints are enrolled through DeskID itself; see [Enroll a fingerprint](#enroll-a-fingerprint). The first successful boot of a sensor build changes the module's factory password from `00000000` to the provisioned value and records that transition in NVS, so an external tool would need the new password afterwards.

### Entering download mode

Two tact switches flank the USB-C connector: **BOOT** on the `GP1`/`GP2` side and **RESET** on the `3V3`/`GP13` side, with the module and RGB LED facing you. Viewing the underside mirrors them, which is the usual reason the sequence appears not to work. They are small enough to need a fingernail or a pen tip.

Use the vendor's one-button entry rather than the two-button dance: unplug, hold **BOOT**, plug the cable in **directly** (a hub makes replug timing unreliable), keep holding about three seconds. `/dev/cu.usbmodem*` appears and `pio run -e deskid-bringup -t upload` works. Holding RESET instead removes the device from USB entirely while held, which is how to tell the two apart.

The board has no auto-reset transistors, so `Hard resetting via RTS pin` at the end of a flash is a no-op — unplug and replug to start the new firmware. `80 F0 00 00 00` reboots into download mode with no button at all, but the ROM comes up in USB-OTG DFU (`303A:0009`) because TinyUSB leaves the shared FSLS PHY mapped to the OTG wrap and that RTC-domain selection survives `esp_restart()`. `esptool` cannot see a DFU device, so the BOOT-hold above is still the reflash path.

## Build and software-only test

```bash
pio test -e native
pio run -e deskid
```

The native suite exercises PIV selection, public card objects, certificate response chaining, malformed APDUs, VERIFY state, user-presence deferral, and `GENERAL AUTHENTICATE`. It runs without the board or sensor.

### Visual simulator

Open the dependency-free simulator before the hardware arrives:

```bash
open tools/simulator.html
```

Start an authentication request, then choose **Match fingerprint**, **No match**, or **Cancel request**. The simulator mirrors the firmware's host-driven CCID time extensions, retry behavior, R503 LED states, and PIV `GENERAL AUTHENTICATE` response; it does not call macOS authentication APIs or emulate a real smart-card reader.

`deskid` is the reversible development target. It uses the temporary TinyUSB development identifiers `CAFE:D15D` and does not enable flash encryption. Those identifiers are forbidden by the production target.

## Provision an identity

Install the pinned host-only tooling inside the ignored build directory:

```bash
python3 -m venv .pio/provisioning-venv
.pio/provisioning-venv/bin/pip install -r tools/requirements-provisioning.txt
```

The certificate must:

- use a P-256 public key matching the private key;
- be currently valid;
- allow `digitalSignature` in Key Usage;
- contain `clientAuth` or Microsoft smart-card-logon OID `1.3.6.1.4.1.311.20.2.2` in Extended Key Usage.

For a local disposable test identity with OpenSSL 3:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out deskid-test.key
chmod 600 deskid-test.key
openssl req -new -x509 -sha256 -days 825 \
  -key deskid-test.key -out deskid-test.crt \
  -subj "/CN=DeskID Test" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=clientAuth,1.3.6.1.4.1.311.20.2.2"
```

Use a CA-issued leaf and a protected manufacturing environment for production. Never commit the generated key or NVS images.

### Development image

```bash
.pio/provisioning-venv/bin/python tools/provision.py \
  --development \
  --certificate deskid-test.crt \
  --private-key deskid-test.key \
  --sensor-password A1B2C3D4
```

This writes `.pio/provisioning/credentials.bin` in plaintext for bring-up. The script validates the identity, requires private-key mode `0600`, rejects the R503 factory password, refuses to overwrite existing output, and deletes temporary DER files.

### On-device key generation

The mode above leaves a copy of the device key on the provisioning host. To avoid that entirely, let the board generate its own key and issue a certificate for the public half:

```bash
.pio/provisioning-venv/bin/python tools/provision.py --on-device --create-ca
.pio/provisioning-venv/bin/python tools/provision.py --on-device \
  --ca-certificate .pio/provisioning/deskid-ca.crt \
  --ca-key .pio/provisioning/deskid-ca.key \
  --common-name "DeskID 001"
```

The script sends `GENERATE ASYMMETRIC KEY PAIR` for slot `9A`, signs the returned P-256 point with the host CA, stores the certificate with `PUT DATA`, reads it back byte-for-byte, and finally has the board sign a random challenge which it verifies against the issued certificate. Only the certificate is written to disk. The CA signing key stays on the host — that is the point of a CA — but no copy of the device key ever exists there.

The board still needs an NVS image for the R503 password, so the packaging mode above remains the first step. All three APDUs are user-presence gated, so a sensor build waits for a fingerprint at each one.

Build, put the board in [download mode](#entering-download-mode), and flash all images in one session:

```bash
pio run -e deskid
~/.platformio/packages/tool-esptoolpy/esptool.py \
  --chip esp32s3 --port /dev/cu.usbmodemXXXX write_flash \
  0x0000 .pio/build/deskid/bootloader.bin \
  0x8000 .pio/build/deskid/partitions.bin \
  0x9000 .pio/provisioning/credentials.bin \
  0x10000 .pio/build/deskid/ota_data_initial.bin \
  0x20000 .pio/build/deskid/firmware.bin
```

### Enroll a fingerprint

A soldered R503 has no UART left for an external enrollment tool, so DeskID enrolls over the card channel:

```bash
python3 tools/hw_smoke_test.py --enroll
```

Touch the sensor, lift when told, then touch the same finger again. Each `80 E1 00 00 00` performs one step of the R503 sequence and returns immediately, so the CCID channel is never held open waiting for a human. The tool prints every stage change and only reports success once the template count in the status object has actually gone up.

**While the library is empty, enrollment needs no authorization.** An empty sensor can never produce a match, so demanding one would make the first finger impossible to enroll — and a device with no enrolled finger cannot sign anything either. Once at least one template exists, `80 E1` is user-presence gated exactly like `0x47`, `0xDB` and `80 F0`: a new finger requires an existing one. Emptying the library needs the R503 password, which only the board holds.

**Press flat and hold for a second.** A held finger gets three match attempts and six capture attempts before the firmware asks for it to lift (`kRetriesPerTouch` in `src/main.cpp`), the way Touch ID keeps trying through a smeared first image. A red flash means the finger has used its attempts: lift and try again. Every rejected match still counts toward the five-failure lockout. If the status object shows `consecutive failed matches: 0` after a timeout, no match was ever rejected: the image never passed quality, and that is the technique, not the finger.

### Production image

Run `tools/provision.py` without `--development`. It produces:

- `.pio/provisioning/credentials.bin`, encrypted with NVS XTS-AES;
- `.pio/provisioning/keys/nvs_keys.bin`, the matching 4 KB NVS key partition.

The `deskid-production` target enables release-mode flash encryption and encrypted NVS. It intentionally refuses to compile until `platformio.ini` contains a VID/PID assigned to this product.

Before any production flash:

1. Obtain an authorized USB VID/PID; never impersonate another product.
2. Configure Secure Boot V2 and an offline signing key in `sdkconfig.production.defaults`. The runtime refuses to sign when Secure Boot or flash encryption is absent.
3. Define and rehearse the eFuse plan on expendable boards, including Secure Boot, flash encryption, anti-rollback, JTAG, and ROM-download policy.
4. Back up the signing and NVS keys under separate access control.
5. Flash `credentials.bin` at `0x9000` and `nvs_keys.bin` at `0xF000` in the same initial session as the signed firmware, before the first release-mode boot.
6. Verify the release image on macOS, Windows `usbccid.sys`, and Linux `pcscd/libccid` before burning final lock bits.

Release flash encryption and eFuse operations are irreversible. Follow Espressif's current [Security Features Enablement Workflows](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/security/security-features-enablement-workflows.html), not copied commands from an older SDK.

## macOS integration

### Touch first

macOS draws its own PIN field for every smart card, at the lock screen and in
`pam_smartcard`, and [no published setting removes it](#does-macos-demand-a-pin).
That is Apple's UI and DeskID cannot replace it. What DeskID can remove is the
waiting on either side of it, and that is what the sequence used to be made of:
click the PIN field, type six meaningless digits, submit, *then* watch a dark
ring start breathing, then reach for it, then wait for the match.

So the ring is live before anything asks. Between host requests the firmware
scans the sensor, and a match is kept for 30 s and spent by the next login
instruction. The gesture becomes:

1. Touch the sensor as you sit down. Solid blue on contact, ~0.8 s to the match.
2. Type any digits and press Return.
3. In. The card answers with no wait at all — status tag `0x0E` reports
   *answered by an earlier touch* and `0x11` counts them.

Measured at the lock screen on 2026-09-02, on a `deskid` board with an R503:
idle match 749 ms finger-on to confirmed, and `GENERAL AUTHENTICATE` released
in **0.2 s** against 30 s of CCID time extensions for the same request without
a touch behind it.

Nothing was touched beforehand? The old path is unchanged: the ring starts
breathing when the request arrives and waits up to 30 s for a finger.

Three things bound the window, because it is the whole security trade:

- **Single use.** Spending it clears it whether or not the signature that
  follows succeeds, so one touch is one operation and it can never be replayed.
- **Login only.** `VERIFY` and `GENERAL AUTHENTICATE` may spend it. Enrolling a
  finger, writing a key or certificate, emptying the sensor and rebooting into
  download mode all still demand a live match while the host waits — those are
  the operations an attacker wants and none of them is on the path this exists
  to shorten. Enforced in `deskid::EarlyTouch::maySpend` and tested in
  `test/test_piv`.
- **30 s**, the same window a request itself waits for a finger. 15 s was the
  first guess and it covered a deliberate touch-click-type-Return but not the
  same sequence at a normal pace, so it is now one number rather than two.
  `kEarlyTouchValidMilliseconds` in `src/main.cpp`; `Device.earlyTouchWindow`
  in the setup app must match.

A rejected idle match costs one rate-limiter attempt and then the ring stops
looking until the finger lifts, so a wallet resting on the sensor cannot walk
the device into a lockout.

**This one needs the blue wire.** `WAKEUP` on `GPIO4` makes each idle poll a
GPIO read at about 5 µA, and contact is answered within 40 ms. There is no
software substitute: the UART fallback used during an authentication is
`GenImg`, a full image capture, and running it continuously power-cycles the
board (see [Fingerprint sensor wiring](#fingerprint-sensor-wiring)). Without the
wire the idle scan does not run and the ring stays dark until a request
arrives. `hw_smoke_test.py --status` reports `wake line (GPIO4)` — touch the
sensor and run it; `high` means the wire is good.

### Guided setup

```bash
tools/deskid-setup
```

A five-step app in the shape macOS uses for Touch ID: connect, enroll a finger, ask for one signature, hand the card to your login, done. It talks to the board through CryptoTokenKit — the same stack `loginwindow` uses — and pairs through `sc_auth`, so it needs no python, no Terminal and no copy of this repository once built. The APDUs are the ones `tools/hw_smoke_test.py` sends, byte for byte, and `tools/deskid-setup --check` proves the parsing against a status object recorded from a real board.

What it is there to prevent, in order of how often each one bites:

- **The touch nobody mentioned.** Pairing makes the card prove it holds the private key, so `sc_auth pair` needs a live fingerprint match inside the same 30 s window as any other signature. Miss it and `sc_auth` reports `6982` with no hint that a finger was ever wanted. The app says so before you click, and shows the ring waiting.
- **Pairing a `deskid-bringup` image**, which approves every presence request with no sensor attached. The app reads the build variant and refuses.
- **Signing in before the sensor can match.** It will not offer the signature test or pairing until a template is enrolled.
- **Not knowing the way out.** The last screen is the daily cheat sheet: any 6–8 digits at the PIN field, touch, and unplug to get your password login back. Unpair is on the pairing screen whenever the card is paired, and needs no admin password.

The launcher compiles `tools/deskid_setup.swift` into `dist/DeskID Setup.app` on first run — roughly half a minute — and ad-hoc signs it with the `com.apple.security.smartcard` entitlement, without which CryptoTokenKit hands a process no slots at all. That is the whole reason it is a bundle rather than a bare binary. No Xcode project, no developer account. `tools/deskid-setup --build` builds without launching; the app can then be opened from Finder or copied to another Mac running macOS 14 or later.

Measured on the bench, 2026-09-01: the app read `5FFF01` over CryptoTokenKit, drove `80 E1` with an enrolled finger already present, and surfaced the board's `6982` refusal with the tap-and-lift advice, all without python on the path.

### The DeskID token driver — why there is no PIN

Apple's built-in `com.apple.CryptoTokenKit.pivtoken` claims any card that answers the PIV AID and hard-codes a PIN for slot `9A`, so on that driver "touch to unlock" is really "type six digits, then touch" ([measured](#does-macos-demand-a-pin)). DeskID therefore ships its own CryptoTokenKit smart-card token, `tools/deskid_token.swift`, built into `DeskID Setup.app` as `Contents/PlugIns/DeskIDToken.appex`:

- The board answers a private AID, `F0 "DeskID"` (`F0 44 65 73 6B 49 44`), so Apple's driver never sees a PIV card. The standard PIV AID is served only when `DESKID_ALLOW_PIV_AID` is set — `deskid-bringup` does, for hosts without the DeskID driver.
- The token publishes the certificate and one signing key with constraint `true`, macOS's word for "always allowed". No PIN is defined, so no PIN field is drawn.
- Every `sign` request becomes `GENERAL AUTHENTICATE` on the board and blocks until the fingerprint gate answers. The extension holds no secret.

Install it from the setup app's pairing screen (**Install DeskID Driver**) or from the command line:

```bash
tools/deskid-setup --install     # copies to /Applications, registers with pluginkit
security list-smartcards         # expect dev.deskid.setup.token:… after a replug
swift tools/pin_probe.swift      # expect a signature, not -1004
```

macOS attaches drivers on card insertion, so a replug is needed after installing. The status object gained tag `0x0D`, finger-on to match-confirmed in milliseconds, so unlock speed is a number rather than an impression.

### Do not create a virtual CryptoTokenKit slot

The requested software-only `TKSmartCardSlot`/`TKSmartCard` provider cannot be implemented with public CryptoTokenKit APIs:

- `TKSmartCardSlotManager` discovers readers that SmartCardServices already knows about; it has no public slot-registration API.
- `TKSmartCard.makeSmartCard()` obtains a client object for an existing slot; it does not publish a card.
- A `TKSmartCardTokenDriver` receives an existing physical smart card and handles high-level key operations. It does not intercept arbitrary inbound APDUs.
- Smart Card Token extensions have no UI. `loginwindow`, CryptoTokenKit, and PAM own authentication prompts, so an extension cannot present a custom **Confirm Login** window.

Consequently, there is no software-only slot to add. A *smart-card* token extension for a real reader is a different thing and is exactly what [the DeskID driver](#the-deskid-token-driver--why-there-is-no-pin) is — which is also why the board stopped answering the PIV AID: two drivers matching one card is a race.

The nearest macOS lab workaround is `vsmartcard`/`ifd-vpcd`, but modern macOS requires a spare physical USB device to trigger loading the legacy IFD bundle. It is brittle test plumbing, not a software-only or production architecture. See the upstream [macOS notes](https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html).

### Hardware smoke test

With a provisioned board connected, exercise it through the macOS PC/SC stack the same way the operating system does:

```bash
python3 tools/hw_smoke_test.py                 # identity and recovery checks
python3 tools/hw_smoke_test.py --repeat 200    # reliability and latency
python3 tools/hw_smoke_test.py --sign          # needs a fingerprint match on sensor builds
python3 tools/hw_smoke_test.py --status --enroll --sign   # first bring-up of a wired sensor
python3 tools/hw_smoke_test.py --quick --status --json    # one JSON object per line
```

`--quick` skips the identity sweep and the card power cycle so a single question costs a single exchange, and `--json` replaces the human report with one JSON object per line — how you script against a board without parsing prose.

The script needs no dependencies: it reaches `PCSC.framework` through `ctypes` and shells out to `openssl` only for the signature check. It verifies the ATR, the exact `SELECT` payload, CCC/CHUID/certificate reads including `61xx` chaining, that the CHUID GUID is the RFC 4122 form of `SHA-256(certificate)[:16]`, that unknown data objects and foreign AIDs are refused with `6A82`, and that the applet survives a CCID power cycle. `--sign` verifies a live `GENERAL AUTHENTICATE` signature against the certificate the board itself serves, which is the only check that proves the stored key, PSA signing, and the PIV response format agree.

Recorded on a wired `deskid` board, 2026-09-01: 0 failures, 20/20 select plus certificate reads at 1 ms median, first fingerprint enrolled (`templates 0 -> 1`), and `--sign` released a signature **10.1 s** after a live match that verifies against the board's own certificate. Without a finger the same request returns `6982` after 30.2 s of CCID time extensions. The certificate the board serves is the one it issued itself — see [On-device key generation](#on-device-key-generation) — so pass `--certificate .pio/provisioning/deskid-device.crt` rather than the default test identity.

### Diagnostics without a serial console

TinyUSB owns the USB PHY and `CONFIG_ESP_CONSOLE_NONE` is set, so USB-Serial-JTAG disappears the moment the firmware boots. PC/SC is the only channel to a running board, so the board answers questions about itself over it:

```bash
python3 tools/hw_smoke_test.py --status
```

`GET DATA 5FFF01` returns firmware version, build variant, uptime, `esp_reset_reason()`, free heap, sensor state and last R503 confirmation byte, whether a credential is present, consecutive failed matches, remaining lockout, how many fingerprint templates the sensor holds, and the level of the wake line. No secrets, no user presence required. It is the difference between guessing which image is on a board and reading it — a `deskid-bringup` unit approves every presence request, and that is not something you want to discover from a stopwatch.

The last field is the wiring check for the blue wire: touch the sensor and run `--status`, and `high` means it is good. `low` means [Touch first](#touch-first) will not run — during an authentication the firmware falls back to a UART probe and only loses a little latency, but the idle scan has no fallback by design.

The same channel reboots the board into download mode with no button press:

```bash
python3 tools/hw_smoke_test.py --download-mode   # or send 80 F0 00 00 00 yourself
```

`80 F0` is user-presence gated, so a host cannot trigger it silently, and it is compiled out of `deskid-production` — `DESKID_ALLOW_DOWNLOAD_MODE` is set only on `deskid` and `deskid-bringup`, and the production environment inherits from `[deskid_common]` so it cannot pick the flag up by accident.

Measured 2026-09-01: the reboot happens, but the ROM comes up in USB-OTG DFU (`303A:0009`) instead of the serial loader, so `pio run -t upload` cannot follow it yet. See [Entering download mode](#entering-download-mode) for why, and for the BOOT-hold that does work.

### Does macOS demand a PIN?

```bash
swift tools/pin_probe.swift              # read-only, changes nothing
swift tools/pin_probe.swift --allow-ui   # same, but let the prompt appear
```

The probe asks macOS to sign with the token key while forbidding authentication UI. A signature means nothing stands between macOS and the card; `LAError.notInteractive` (`-1004`) means macOS was about to ask for a PIN. Measured against Apple's stock `pivtoken` on 2026-09-01: **a PIN is required.** `sc_auth verifypin -t <token-id> -p 123456` then returns *PIN verified*, because the applet accepts any eight-byte PIN block once the fingerprint gate is satisfied.

### Pair the physical DeskID token

Install and trust the issuing CA in the System keychain for a test machine. Keep a separate recovery administrator account before changing smart-card login policy. Then connect DeskID and verify in order:

```bash
pluginkit -m -p com.apple.ctk-tokens
system_profiler SPSmartCardsDataType
security list-smartcards
sc_auth identities
```

`sc_auth identities` should show the certificate from PIV slot `9A`. Pair the exact hash it reports:

```bash
sudo sc_auth pair -u "$(whoami)" -h "<identity-hash>"
sudo -k
sudo true
```

Or let the wrapper find the hash, run the preflight, and unwind the pairing if any step after it fails:

```bash
tools/sc_auth_gate.sh status
sudo -v                         # get the password prompt out of the way first
tools/sc_auth_gate.sh pair      # then touch the sensor when the ring lights
tools/sc_auth_gate.sh unpair    # undo; this one does not need root
```

**Pairing needs a fingerprint.** `sc_auth pair` asks the card to prove it holds the private key, which is an ordinary `GENERAL AUTHENTICATE` and therefore an ordinary presence gate: touch the enrolled finger within 30 s or pairing fails with `CryptoTokenKit error -3 - SmartCard returned error 6982`. Nothing is changed when it does. Authenticating `sudo` first means the whole window belongs to your finger rather than to the password prompt. [The setup app](#guided-setup) does this sequencing for you.

The fastest escape hatch is unplugging the token, which returns the login window to password entry. Check `sc_auth filevault -o status` first: if card-based FileVault is unavailable for the account, the preboot screen always takes the password and pairing cannot lock you out of a boot.

Do not enforce smart-card-only login until sudo and logout/login recovery have both been tested. Apple documents policy and recovery behavior in [Intro to smart card integration](https://support.apple.com/guide/deployment/intro-to-smart-card-integration-depd0b888248/web).

#### Removing the "or password" choice

Pairing adds DeskID to the lock screen; it does not remove what was already
there. On a MacBook the screen still offers the built-in Touch ID and the
password, and the smart-card field has to be picked out of them — which is the
first thing users notice and the one part of the sequence that is a setting
rather than a limitation. `enforceSmartCard` is the setting
([Configure macOS for smart card-only authentication](https://support.apple.com/en-ca/guide/deployment/depfce8de48b/1/web/1.0)):

```bash
sudo defaults write /Library/Preferences/com.apple.security.smartcard enforceSmartCard -bool true
```

It stops all password-based authentication, so **do not run it without an
escape hatch already in place**, in this order:

1. A second administrator account that is *not* card-paired, tested by logging
   into it.
2. `sc_auth filevault -o status`. If card-based FileVault is unavailable for
   the account, the preboot screen always takes the password and a bad policy
   cannot cost you a boot — verify that rather than assume it.
3. `/private/etc/SmartcardLogin.plist` with a `NotEnforcedGroup` naming a group
   that recovery account belongs to. This is the undo that works while locked
   out; `defaults delete … enforceSmartCard` needs a shell you may not have.

Unplugging DeskID does **not** return you to password login once this is set —
that shortcut only works while enforcement is off. `allowUnmappedUsers -int 1`
lets accounts with no pairing keep their passwords, which is the milder version
of the same policy and the right one on a shared machine.

The built-in PIV flow **does** display a PIN field, because PIV slot `9A` is defined as PIN-protected; that is measured, not assumed. DeskID ignores the entered PIN value but requires the standard eight-byte VERIFY APDU and a live R503 match, so any six to eight digits are accepted. Public CryptoTokenKit APIs cannot replace that system prompt with a custom biometric dialog; the blue hardware ring is the user-presence cue, and [Touch first](#touch-first) is how the prompt stops costing anything.

## Security limits

- R503 UART responses are not cryptographically authenticated. An attacker with physical access to the internal UART may be able to inject a successful match result.
- ESP32-S3 encrypted flash and Secure Boot harden key storage but are not a discrete secure element and do not eliminate runtime extraction, fault-injection, or side-channel risks.
- The R503 password is only 32 bits. It prevents accidental access, not determined physical attack.
- Host provisioning leaves another copy of the private key under manufacturing control. Use `tools/provision.py --on-device` so the key is generated on the board and never exists on the host; the NVS packaging mode is still needed for the R503 password. A secure element remains a separate, unaddressed question.
- `80 F0` reboots the device into ROM download mode. It requires a fingerprint match and is absent from production builds, but on development builds it is a firmware-replacement path for anyone who can obtain one match.
- Fingerprint templates remain inside the R503. `80 E1` enrolls without authorization while the library is empty, because an empty sensor cannot match and would otherwise be unenrollable; once it holds a template a match is required. Deletion and recovery still need a separate authenticated process.

For a high-assurance commercial device, add a reviewed secure element and a sensor-to-authenticator channel with cryptographic match attestation. The listed ESP32-S3 and R503 alone cannot provide the physical-tamper guarantees of Touch ID.