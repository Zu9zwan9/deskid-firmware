#!/usr/bin/env python3
# Copyright (c) 2026 Maksym Bardakh. All rights reserved.
# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Source-available under LICENSE.md with the permissions in LICENSING.md.
"""Exercise a connected DeskID board through the macOS PC/SC stack.

Talks to the real reader the same way the operating system does, so a pass
here means the CCID transport and the PIV applet work on silicon rather than
only in the native unit tests.

    python3 tools/hw_smoke_test.py
    python3 tools/hw_smoke_test.py --repeat 20
    python3 tools/hw_smoke_test.py --sign          # needs user presence
    python3 tools/hw_smoke_test.py --nonce         # one digest signed twice, two touches
    python3 tools/hw_smoke_test.py --enroll        # guided fingerprint enrollment

Standard library only: PCSC.framework through ctypes, openssl(1) for the
signature check.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 1
SCARD_PROTOCOL_T1 = 2
SCARD_LEAVE_CARD = 0
SCARD_UNPOWER_CARD = 2

PIV_AID = bytes.fromhex("A000000308")
DESKID_AID = bytes.fromhex("F04465736B4944")  # F0 "DeskID"; see deskid_core.cpp
SELECT_PIV = bytes.fromhex("00A4040007") + DESKID_AID
SELECT_RESPONSE = bytes.fromhex("61114F0600001000010079074F05") + PIV_AID
TAG_CCC = bytes.fromhex("5FC107")
TAG_CHUID = bytes.fromhex("5FC102")
TAG_CERTIFICATE = bytes.fromhex("5FC105")
TAG_UNKNOWN = bytes.fromhex("5FC101")
TAG_STATUS = bytes.fromhex("5FFF01")
DOWNLOAD_MODE = bytes.fromhex("80F0000000")
DEFAULT_CERTIFICATE = Path(".pio/provisioning/deskid-device.crt")

BUILD_VARIANTS = {0: "production", 1: "deskid", 2: "bringup"}
SENSOR_STATES = {0: "absent/unknown", 1: "ready", 2: "error"}
RESET_REASONS = {
    0: "unknown", 1: "power-on", 2: "external pin", 3: "esp_restart",
    4: "panic", 5: "interrupt watchdog", 6: "task watchdog", 7: "other watchdog",
    8: "deep sleep", 9: "brownout", 10: "SDIO", 11: "USB", 12: "JTAG",
    13: "efuse error", 14: "power glitch", 15: "CPU lockup",
}

SW_OK = 0x9000
SW_FILE_NOT_FOUND = 0x6A82
SW_SECURITY_NOT_SATISFIED = 0x6982
SW_AUTHENTICATION_BLOCKED = 0x6983
SW_INSTRUCTION_NOT_SUPPORTED = 0x6D00

ENROLL_STEP = bytes.fromhex("80E1000000")
ENROLL_STAGE_DONE = 0x03
ENROLL_STAGE_FAILED = 0xFF
ENROLL_STAGES = {
    0x00: "place your finger",
    0x04: "lift your finger off the sensor",
    ENROLL_STAGE_DONE: "stored",
    ENROLL_STAGE_FAILED: "that image was not usable — lift and place the finger again",
}
# One image is one template, and a finger is a set of them: the sensor sees a
# part of the finger at a time, so the placements have to cover how it lands
# in daily use. kEnrollmentSessionTemplates in the firmware is how many one
# authorizing match pays for.
ENROLL_PLACEMENTS = (
    "flat, the way you normally touch",
    "the same again",
    "a little to the left",
    "a little to the right",
    "a little toward the fingertip",
    "a little toward the joint",
    "rolled slightly onto its left edge",
    "rolled slightly onto its right edge",
    "the way you touch in a hurry",
    "in a hurry again",
    "from the side your hand comes from",
    "normally, one last time",
)
ENROLL_ERRORS = {
    SW_SECURITY_NOT_SATISFIED: "6982 — an already enrolled finger has to match first",
    SW_AUTHENTICATION_BLOCKED: "6983 — the rate limiter has locked the sensor out",
    SW_INSTRUCTION_NOT_SUPPORTED: "6D00 — the flashed image is deskid-bringup, which has no sensor",
}
# The ring waits 30 s for the authorizing match, and the match, like each
# stored placement after it, keeps the enrollment open for 60 s
# (kEnrollmentSessionMilliseconds).
ENROLL_TIMEOUT_SECONDS = 90.0
ENROLL_POLL_SECONDS = 0.25
# Unusable images in a row, for one placement.
ENROLL_FAILURE_LIMIT = 8

# kAuthenticationTimeoutMilliseconds in src/main.cpp. Only used to tell the
# operator how long the blue ring will wait, so drift costs a wrong countdown
# and nothing else.
PRESENCE_TIMEOUT_SECONDS = 30.0


# --json turns every line of the human report into one JSON object so
# tools/deskid_setup.swift can follow a live enrollment or signature without
# scraping prose. The two modes are exclusive: one writer owns stdout.
EVENTS = False


def say(text: str) -> None:
    if not EVENTS:
        print(text)


def emit(event: str, **fields: object) -> None:
    if EVENTS:
        print(json.dumps({"event": event, **fields}), flush=True)


class SCardIoRequest(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("dwProtocol", ctypes.c_uint32), ("cbPciLength", ctypes.c_uint32)]


class PcscError(RuntimeError):
    pass


pcsc = ctypes.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")


def check(name: str, code: int) -> None:
    if code != 0:
        raise PcscError(f"{name} failed: 0x{code & 0xFFFFFFFF:08X}")


def list_readers(context: ctypes.c_int32) -> list[str]:
    length = ctypes.c_uint32(0)
    check("SCardListReaders", pcsc.SCardListReaders(context, None, None, ctypes.byref(length)))
    buffer = ctypes.create_string_buffer(length.value)
    check(
        "SCardListReaders",
        pcsc.SCardListReaders(context, None, buffer, ctypes.byref(length)),
    )
    return [name.decode() for name in buffer.raw[: length.value].split(b"\0") if name]


class Card:
    """One PC/SC connection, held inside a transaction so the macOS PIV token
    driver cannot interleave its own APDUs into our chained reads."""

    def __init__(self, context: ctypes.c_int32, reader: str) -> None:
        self.context = context
        self.reader = reader
        self.handle = ctypes.c_int32(0)
        protocol = ctypes.c_uint32(0)
        check(
            "SCardConnect",
            pcsc.SCardConnect(
                context,
                reader.encode(),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                ctypes.byref(self.handle),
                ctypes.byref(protocol),
            ),
        )
        self.protocol = protocol.value
        self.pci = SCardIoRequest.in_dll(
            pcsc, "g_rgSCardT1Pci" if self.protocol == SCARD_PROTOCOL_T1 else "g_rgSCardT0Pci"
        )
        check("SCardBeginTransaction", pcsc.SCardBeginTransaction(self.handle))

    def atr(self) -> bytes:
        atr = (ctypes.c_ubyte * 33)()
        atr_length = ctypes.c_uint32(len(atr))
        state = ctypes.c_uint32(0)
        protocol = ctypes.c_uint32(0)
        name_length = ctypes.c_uint32(0)
        check(
            "SCardStatus",
            pcsc.SCardStatus(
                self.handle,
                None,
                ctypes.byref(name_length),
                ctypes.byref(state),
                ctypes.byref(protocol),
                atr,
                ctypes.byref(atr_length),
            ),
        )
        return bytes(atr[: atr_length.value])

    def transmit(self, apdu: bytes) -> bytes:
        received = (ctypes.c_ubyte * 4096)()
        received_length = ctypes.c_uint32(len(received))
        check(
            "SCardTransmit",
            pcsc.SCardTransmit(
                self.handle,
                ctypes.byref(self.pci),
                (ctypes.c_ubyte * len(apdu))(*apdu),
                len(apdu),
                None,
                received,
                ctypes.byref(received_length),
            ),
        )
        return bytes(received[: received_length.value])

    def send(self, apdu: bytes) -> tuple[bytes, int, float]:
        """Send one APDU, draining 61xx continuations. Returns data, SW, seconds."""
        started = time.monotonic()
        response = self.transmit(apdu)
        data = b""
        while len(response) >= 2 and response[-2] == 0x61:
            data += response[:-2]
            response = self.transmit(bytes([0x00, 0xC0, 0x00, 0x00, response[-1]]))
        if len(response) < 2:
            raise PcscError(f"short response: {response.hex()}")
        data += response[:-2]
        return data, (response[-2] << 8) | response[-1], time.monotonic() - started

    def close(self, disposition: int = SCARD_LEAVE_CARD) -> None:
        pcsc.SCardEndTransaction(self.handle, disposition)
        pcsc.SCardDisconnect(self.handle, disposition)


def read_tlv(data: bytes) -> dict[int, bytes]:
    """Flat BER-TLV walk. Single-byte tags are all the PIV objects use."""
    values: dict[int, bytes] = {}
    offset = 0
    while offset + 2 <= len(data):
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[offset : offset + count], "big")
            offset += count
        values[tag] = data[offset : offset + length]
        offset += length
    return values


def certificate_from_object(data: bytes) -> bytes:
    outer = read_tlv(data).get(0x53)
    if outer is None:
        raise ValueError("certificate object is not wrapped in tag 0x53")
    inner = read_tlv(outer).get(0x70)
    if inner is None:
        raise ValueError("certificate object carries no tag 0x70")
    return inner


def pem_to_der(path: Path) -> bytes:
    text = path.read_text()
    if "-----BEGIN" not in text:
        return path.read_bytes()
    body = text.split("-----BEGIN CERTIFICATE-----")[1].split("-----END")[0]
    return base64.b64decode("".join(body.split()))


def verify_signature(certificate: bytes, digest: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "cert.der").write_bytes(certificate)
        (root / "digest.bin").write_bytes(digest)
        (root / "sig.der").write_bytes(signature)
        public_key = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", str(root / "cert.der"),
             "-pubkey", "-noout"],
            capture_output=True,
            check=True,
        ).stdout
        (root / "pub.pem").write_bytes(public_key)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(root / "pub.pem"),
             "-in", str(root / "digest.bin"), "-sigfile", str(root / "sig.der")],
            capture_output=True,
        )
        return result.returncode == 0


class Report:
    def __init__(self) -> None:
        self.failures = 0

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        if not passed:
            self.failures += 1
        say(f"  {'PASS' if passed else 'FAIL'}  {name}{'  ' + detail if detail else ''}")
        emit("check", name=name, passed=passed, detail=detail)
        return passed

    def note(self, name: str, detail: str) -> None:
        say(f"  ....  {name}  {detail}")
        emit("note", name=name, detail=detail)


def get_data(card: Card, tag: bytes) -> tuple[bytes, int, float]:
    return card.send(bytes([0x00, 0xCB, 0x3F, 0xFF, len(tag) + 2, 0x5C, len(tag)]) + tag + b"\x00")


def general_authenticate(digest: bytes) -> bytes:
    body = bytes([0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]) + digest
    return bytes([0x00, 0x87, 0x11, 0x9A, len(body)]) + body + b"\x00"


def status_object(card: Card) -> dict[int, bytes]:
    """The 5FFF01 fields as tag -> value, empty when the object cannot be read."""
    data, status, _ = get_data(card, TAG_STATUS)
    return read_tlv(read_tlv(data).get(0x53, b"")) if status == SW_OK else {}


def status_number(fields: dict[int, bytes], tag: int) -> int:
    return int.from_bytes(fields.get(tag, b""), "big")


def run_identity_checks(card: Card, report: Report, expected_certificate: bytes | None) -> None:
    atr = card.atr()
    report.check("ATR present", len(atr) >= 2, atr.hex(" ").upper())
    report.note("protocol", "T=1" if card.protocol == SCARD_PROTOCOL_T1 else "T=0")

    data, status, elapsed = card.send(SELECT_PIV)
    report.check("SELECT PIV AID returns 9000", status == SW_OK, f"{elapsed * 1000:.0f} ms")
    report.check("SELECT payload matches applet contract", data == SELECT_RESPONSE, data.hex().upper())

    _, status, _ = get_data(card, TAG_UNKNOWN)
    report.check("unknown data object rejected with 6A82", status == SW_FILE_NOT_FOUND, f"{status:04X}")

    _, status, _ = card.send(bytes.fromhex("00A4040005A000000399"))
    report.check("foreign AID rejected with 6A82", status == SW_FILE_NOT_FOUND, f"{status:04X}")

    data, status, _ = get_data(card, TAG_CCC)
    if status == SW_FILE_NOT_FOUND:
        _, chuid_status, _ = get_data(card, TAG_CHUID)
        _, certificate_status, _ = get_data(card, TAG_CERTIFICATE)
        report.check(
            "board is unprovisioned, CCC, CHUID and certificate all return 6A82",
            chuid_status == SW_FILE_NOT_FOUND and certificate_status == SW_FILE_NOT_FOUND,
            "run tools/provision.py to issue a credential",
        )
        return
    report.check("GET DATA CCC (5FC107)", status == SW_OK and data[:1] == b"\x53", f"{len(data)} bytes")

    chuid, status, _ = get_data(card, TAG_CHUID)
    report.check("GET DATA CHUID (5FC102)", status == SW_OK and chuid[:1] == b"\x53", f"{len(chuid)} bytes")

    certificate_object, status, elapsed = get_data(card, TAG_CERTIFICATE)
    if not report.check(
        "GET DATA certificate (5FC105), chained",
        status == SW_OK,
        f"{len(certificate_object)} bytes in {elapsed * 1000:.0f} ms",
    ):
        return
    certificate = certificate_from_object(certificate_object)
    report.note("certificate", f"{len(certificate)} bytes DER")

    # The applet derives the GUID from the certificate and stamps RFC 4122
    # version 4 and variant bits over it, which is what macOS shows as the
    # token instance identifier.
    identifier = bytearray(hashlib.sha256(certificate).digest()[:16])
    identifier[6] = (identifier[6] & 0x0F) | 0x40
    identifier[8] = (identifier[8] & 0x3F) | 0x80
    guid = read_tlv(read_tlv(chuid).get(0x53, b"")).get(0x34)
    report.check(
        "CHUID GUID is RFC 4122 SHA-256(certificate)[:16]",
        guid == bytes(identifier),
        (guid or b"").hex().upper(),
    )
    if expected_certificate is not None:
        report.check(
            "device certificate matches the provisioned one",
            certificate == expected_certificate,
        )


def run_power_cycle(context: ctypes.c_int32, reader: str, report: Report) -> None:
    card = Card(context, reader)
    card.close(SCARD_UNPOWER_CARD)
    time.sleep(0.3)
    card = Card(context, reader)
    try:
        _, status, elapsed = card.send(SELECT_PIV)
        report.check(
            "survives card power cycle (IccPowerOff/On)",
            status == SW_OK,
            f"{elapsed * 1000:.0f} ms",
        )
    finally:
        card.close()


def run_repeat(context: ctypes.c_int32, reader: str, report: Report, count: int) -> None:
    timings: list[float] = []
    failures = 0
    for _ in range(count):
        card = Card(context, reader)
        try:
            _, select_status, select_time = card.send(SELECT_PIV)
            _, read_status, read_time = get_data(card, TAG_CERTIFICATE)
            if select_status != SW_OK or read_status != SW_OK:
                failures += 1
            timings.append(select_time + read_time)
        finally:
            card.close()
    report.check(
        f"{count} consecutive select + certificate reads",
        failures == 0,
        f"{count - failures}/{count} ok, "
        f"min {min(timings) * 1000:.0f} / median {statistics.median(timings) * 1000:.0f} / "
        f"max {max(timings) * 1000:.0f} ms",
    )


def run_sign(card: Card, report: Report) -> None:
    card.send(SELECT_PIV)
    digest = hashlib.sha256(os.urandom(32)).digest()
    say("  ....  requesting a signature — touch the sensor if one is attached")
    emit("waiting", what="signature", seconds=PRESENCE_TIMEOUT_SECONDS)
    data, status, elapsed = card.send(general_authenticate(digest))
    emit("signed", status=f"{status:04X}", seconds=round(elapsed, 1))
    if status == SW_OK:
        signature = read_tlv(read_tlv(data).get(0x7C, b"")).get(0x82)
        report.check("GENERAL AUTHENTICATE returned a signature", signature is not None,
                     f"{elapsed:.1f} s")
        if signature is None:
            return
        certificate_object, _, _ = get_data(card, TAG_CERTIFICATE)
        report.check(
            "signature verifies against the device certificate",
            verify_signature(certificate_from_object(certificate_object), digest, signature),
        )
        # Gate outcome 1 is a match made inside this request. A stuck wake
        # line once dated contact from the start of the wait, 27 s here.
        fields = status_object(card)
        if 0x0D in fields and status_number(fields, 0x0E) == 1:
            report.check("match confirmed within 5 s of contact",
                         status_number(fields, 0x0D) < 5000,
                         f"{status_number(fields, 0x0D)} ms")
        if elapsed < 1.0:
            # A fast signature used to mean one thing. It now means two, and
            # only the board can say which: a touch given before the request
            # (gate outcome 7) is the product working, a build that approves
            # everything is not.
            gate = status_number(status_object(card), 0x0E)
            report.note("build",
                        "answered by a touch given before the request"
                        if gate == 7 else
                        "signed with no user presence — this is deskid-bringup")
        return
    if status == SW_SECURITY_NOT_SATISFIED:
        report.note("result", f"6982 after {elapsed:.1f} s — presence gate held, no match")
        report.check("user presence gate refused rather than hung", elapsed > 1.0, f"{elapsed:.1f} s")
        return
    if status == SW_AUTHENTICATION_BLOCKED:
        report.note("result", f"6983 after {elapsed:.1f} s — rate limiter locked out")
        return
    report.check("GENERAL AUTHENTICATE", False, f"SW {status:04X}")


def run_nonce(card: Card, report: Report) -> None:
    """Two signatures of one digest, which takes two touches.

    The firmware hedges its nonce: fresh randomness goes in beside the key and
    the digest. So the two signatures must differ. Plain RFC 6979 would return
    the first one again, and a fault during one of two such signatures is how
    that scheme loses a key.
    """
    card.send(SELECT_PIV)
    digest = hashlib.sha256(os.urandom(32)).digest()
    certificate_object, _, _ = get_data(card, TAG_CERTIFICATE)
    certificate = certificate_from_object(certificate_object)
    signatures = []
    for attempt in ("first", "second"):
        say(f"  ....  {attempt} signature of the same digest: touch the sensor")
        emit("waiting", what=f"{attempt} signature", seconds=PRESENCE_TIMEOUT_SECONDS)
        data, status, elapsed = card.send(general_authenticate(digest))
        emit("signed", status=f"{status:04X}", seconds=round(elapsed, 1))
        signature = read_tlv(read_tlv(data).get(0x7C, b"")).get(0x82) if status == SW_OK else None
        if not report.check(f"{attempt} signature verifies against the device certificate",
                            signature is not None
                            and verify_signature(certificate, digest, signature),
                            f"SW {status:04X} in {elapsed:.1f} s"):
            return
        signatures.append(signature)
    report.check("two signatures of one digest differ", signatures[0] != signatures[1])


def run_status(card: Card, report: Report) -> None:
    card.send(SELECT_PIV)
    data, status, _ = get_data(card, TAG_STATUS)
    if not report.check("GET DATA status (5FFF01)", status == SW_OK, f"SW {status:04X}"):
        return
    fields = read_tlv(read_tlv(data).get(0x53, b""))
    if not report.check("status object is wrapped in tag 0x53", bool(fields)):
        return

    def number(tag: int) -> int:
        return int.from_bytes(fields.get(tag, b""), "big")

    variant = number(0x02)
    reason = number(0x04)
    sensor = number(0x06)
    report.note("firmware", fields.get(0x01, b"").decode(errors="replace") or "(none)")
    report.note("build variant", f"{variant} ({BUILD_VARIANTS.get(variant, 'unknown')})")
    report.note("uptime", f"{number(0x03)} s")
    report.note("reset reason", f"{reason} ({RESET_REASONS.get(reason, 'unknown')})")
    report.note("free heap", f"{number(0x05)} bytes")
    report.note("sensor", f"{sensor} ({SENSOR_STATES.get(sensor, 'unknown')})")
    report.note("last sensor confirmation", f"0x{number(0x07):02X}")
    report.note("credential present", "yes" if number(0x08) else "no")
    report.note("consecutive failed matches", str(number(0x09)))
    report.note("fingerprint lockout", f"{number(0x0A)} s remaining")
    report.note("enrolled templates", str(number(0x0B)))
    # The R503 rests high and reads low for as long as a finger is on the ring.
    report.note("wake line (GPIO4)", "high" if number(0x0C) else "low")
    report.note("last match, finger-on to confirmed",
                f"{number(0x0D)} ms" if 0x0D in fields else "not reported by this firmware")
    outcomes = {0: "none yet", 1: "matched", 2: "timed out, no finger", 3: "aborted by host",
                4: "card re-powered", 5: "rate-limiter lockout", 6: "sensor absent",
                7: "answered by an earlier touch"}
    report.note("last presence gate", f"{outcomes.get(number(0x0E), number(0x0E))}"
                f" (INS {number(0x0F):02X})")
    report.note("pin-pad (Secure) requests since boot", str(number(0x10)))
    report.note("gates answered by an earlier touch", str(number(0x11)))
    report.note("touch still spendable",
                f"{number(0x12)} s" if number(0x12) else "no")
    biases = {0b10: "floating — nothing is driving it",
              0b11: "driven high", 0b00: "driven low"}
    report.note("ring armed by host",
                f"{number(0x14)} s remaining" if number(0x14) else "no")
    report.note("wake line bias probe",
                biases.get(number(0x13), f"0b{number(0x13):02b}")
                if 0x13 in fields else "not reported by this firmware")
    if 0x15 in fields:
        report.check("signing self-test reproduced its known answer", number(0x15) == 1,
                     "passed" if number(0x15) == 1 else "failed, the board refuses to sign")
    else:
        report.note("signing self-test", "not reported by this firmware")
    emit("status",
         firmware=fields.get(0x01, b"").decode(errors="replace"),
         variant=variant,
         variantName=BUILD_VARIANTS.get(variant, "unknown"),
         uptime=number(0x03),
         heap=number(0x05),
         sensor=sensor,
         sensorName=SENSOR_STATES.get(sensor, "unknown"),
         confirmation=number(0x07),
         credential=bool(number(0x08)),
         failures=number(0x09),
         lockout=number(0x0A),
         templates=number(0x0B),
         wake=bool(number(0x0C)),
         matchMilliseconds=number(0x0D),
         earlyTouchGates=number(0x11),
         touchValidSeconds=number(0x12))
    report.check("status object carries every field",
                 set(fields) >= {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                 0x0B, 0x0C})


def run_enroll(card: Card, report: Report, placements: int) -> None:
    card.send(SELECT_PIV)
    fields = status_object(card)
    if not report.check("GET DATA status (5FFF01) before enrolling", bool(fields)):
        return
    before = status_number(fields, 0x0B)
    report.note("enrolled templates", str(before))
    report.note("authorization",
                "an already enrolled finger has to match first" if before
                else "the sensor is empty, so this first finger enrolls freely")

    deadline = time.monotonic() + ENROLL_TIMEOUT_SECONDS
    problem = f"no placement within {ENROLL_TIMEOUT_SECONDS:.0f} s"
    stage: int | None = None
    failures = 0
    stored = 0
    while stored < placements and time.monotonic() < deadline:
        data, status, _ = card.send(ENROLL_STEP)
        if status != SW_OK or len(data) != 1:
            problem = ENROLL_ERRORS.get(status, f"SW {status:04X}")
            break
        if data[0] != stage:
            stage = data[0]
            message = ENROLL_STAGES.get(stage, f"unknown stage 0x{stage:02X}")
            if stage == 0x00:
                hint = ENROLL_PLACEMENTS[stored % len(ENROLL_PLACEMENTS)]
                message += f", {stored + 1} of {placements}: {hint}"
            say(f"  ....  {message}")
            emit("enroll", stage=stage, message=message, stored=stored)
            if stage == ENROLL_STAGE_FAILED:
                failures += 1
        if stage == ENROLL_STAGE_DONE:
            stored += 1
            failures = 0
            stage = None  # the next poll says what comes after
            deadline = time.monotonic() + ENROLL_TIMEOUT_SECONDS
        if failures >= ENROLL_FAILURE_LIMIT:
            problem = f"{failures} unusable images in a row"
            break
        time.sleep(ENROLL_POLL_SECONDS)

    fields = status_object(card)
    after = status_number(fields, 0x0B)
    complete = stored == placements and after - before == stored
    if report.check("enroll a finger", complete,
                    f"templates {before} -> {after}" if complete
                    else f"{problem}; stored {stored} of {placements}, "
                         f"templates {before} -> {after}"):
        return
    sensor = status_number(fields, 0x06)
    report.note("sensor", f"{sensor} ({SENSOR_STATES.get(sensor, 'unknown')})")
    report.note("last sensor confirmation", f"0x{status_number(fields, 0x07):02X}")


# PC/SC part 10: ask the reader driver which pinpad features it exposes, then
# drive one. FEATURE_VERIFY_PIN_DIRECT is what macOS uses when a token asks
# for the reader to collect the PIN itself.
CM_IOCTL_GET_FEATURE_REQUEST = 0x42000000 + 3400
FEATURE_VERIFY_PIN_DIRECT = 0x06


def scard_control(card: Card, code: int, payload: bytes) -> bytes:
    # macOS exports the pcsc-lite 1.1 SCardControl (no control code) under the
    # plain name; the modern signature is SCardControl132.
    control = pcsc.SCardControl132
    control.argtypes = [ctypes.c_int32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    control.restype = ctypes.c_int32
    received = (ctypes.c_ubyte * 256)()
    returned = ctypes.c_uint32(0)
    sent = (ctypes.c_ubyte * max(len(payload), 1))(*payload)
    check("SCardControl132",
          control(card.handle, code, sent if payload else None, len(payload),
                  received, len(received), ctypes.byref(returned)))
    return bytes(received[: returned.value])


def run_pinpad(card: Card, report: Report) -> None:
    """VERIFY through the reader's own PIN pad — for DeskID, the fingerprint ring."""
    card.send(SELECT_PIV)
    features = scard_control(card, CM_IOCTL_GET_FEATURE_REQUEST, b"")
    codes: dict[int, int] = {}
    offset = 0
    while offset + 6 <= len(features):
        codes[features[offset]] = int.from_bytes(features[offset + 2 : offset + 6], "big")
        offset += 2 + features[offset + 1]
    if not report.check("reader driver exposes FEATURE_VERIFY_PIN_DIRECT",
                        FEATURE_VERIFY_PIN_DIRECT in codes,
                        "features " + ", ".join(f"{k:02X}" for k in codes) or "none"):
        return

    verify = bytes.fromhex("0020008008") + b"\xFF" * 8
    structure = (
        bytes([30, 30])             # bTimerOut, bTimerOut2 — seconds the pad may wait
        + bytes([0x82])             # bmFormatString: ASCII, left-justified, PIN at byte 0 of block
        + bytes([0x08])             # bmPINBlockString: 8-byte block, no length field
        + bytes([0x00])             # bmPINLengthFormat
        + bytes([0x08, 0x04])       # wPINMaxExtraDigit: max 8, min 4
        + bytes([0x02])             # bEntryValidationCondition: validation key pressed
        + bytes([0x01])             # bNumberMessage
        + bytes([0x09, 0x04])       # wLangId: en-US
        + bytes([0x00])             # bMsgIndex
        + bytes([0x00, 0x00, 0x00]) # bTeoPrologue
        + len(verify).to_bytes(4, "little")
        + verify
    )
    say("  ....  VERIFY via the reader's PIN pad — touch the sensor")
    emit("waiting", what="pinpad verify", seconds=PRESENCE_TIMEOUT_SECONDS)
    started = time.monotonic()
    response = scard_control(card, codes[FEATURE_VERIFY_PIN_DIRECT], structure)
    elapsed = time.monotonic() - started
    status = int.from_bytes(response[-2:], "big") if len(response) >= 2 else 0
    emit("pinpad", status=f"{status:04X}", seconds=round(elapsed, 1))
    report.check("pad VERIFY answered 9000 after a fingerprint match", status == SW_OK,
                 f"SW {status:04X} after {elapsed:.1f} s")
    if status == SW_OK:
        _, after, _ = card.send(bytes.fromhex("0020008000"))
        report.check("card reports verified state afterwards", after == SW_OK, f"SW {after:04X}")


def run_download_mode(card: Card, report: Report) -> None:
    card.send(SELECT_PIV)
    say("  ....  requesting download mode — touch the sensor if one is attached")
    try:
        _, status, elapsed = card.send(DOWNLOAD_MODE)
    except PcscError:
        # The board may reboot before the response reaches the reader.
        report.note("result", "the reader lost the card, which is what rebooting looks like")
        return
    if status == SW_INSTRUCTION_NOT_SUPPORTED:
        report.check("enter download mode", False,
                     "6D00 — this build has no DESKID_ALLOW_DOWNLOAD_MODE")
        return
    report.check("enter download mode (80F0)", status == SW_OK, f"SW {status:04X} in {elapsed:.1f} s")
    if status == SW_OK:
        report.note("next", "the board is entering ROM DFU download mode (303A:0009); "
                            "esptool cannot see it — hold BOOT and replug for the serial loader")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reader", default="DeskID", help="substring of the PC/SC reader name")
    parser.add_argument("--certificate", type=Path, default=DEFAULT_CERTIFICATE,
                        help="certificate the board was provisioned with, for comparison")
    parser.add_argument("--repeat", type=int, default=0, help="reliability loop iterations")
    parser.add_argument("--sign", action="store_true",
                        help="request a signature; needs a fingerprint match on sensor builds")
    parser.add_argument("--nonce", action="store_true",
                        help="sign one digest twice and require different signatures; two touches")
    parser.add_argument("--status", action="store_true",
                        help="read the diagnostic status object (5FFF01)")
    parser.add_argument("--enroll", action="store_true",
                        help="enroll a fingerprint on the sensor, guided and interactive")
    parser.add_argument("--placements", type=int, default=len(ENROLL_PLACEMENTS),
                        help="how many placements of the finger --enroll records "
                             "(default %(default)s)")
    parser.add_argument("--pinpad", action="store_true",
                        help="VERIFY through the reader's PIN pad, i.e. the fingerprint ring")
    parser.add_argument("--download-mode", action="store_true",
                        help="reboot the board into ROM download mode (lands in USB-OTG DFU)")
    parser.add_argument("--quick", action="store_true",
                        help="skip the identity sweep and card power cycle; run only what is asked")
    parser.add_argument("--json", action="store_true",
                        help="one JSON object per line instead of the human report")
    arguments = parser.parse_args()

    global EVENTS
    EVENTS = arguments.json

    context = ctypes.c_int32(0)
    check(
        "SCardEstablishContext",
        pcsc.SCardEstablishContext(SCARD_SCOPE_SYSTEM, None, None, ctypes.byref(context)),
    )
    try:
        readers = list_readers(context)
        say(f"readers: {readers or '(none)'}")
        matching = [name for name in readers if arguments.reader in name]
        emit("readers", readers=readers, reader=matching[0] if matching else None)
        if not matching:
            say(f"no reader matching {arguments.reader!r} — is the board plugged in?")
            return 1
        reader = matching[0]

        report = Report()

        if not arguments.quick:
            say(f"\nidentity — {reader}")
            expected = pem_to_der(arguments.certificate) if arguments.certificate.exists() else None
            if expected is None:
                if arguments.certificate == DEFAULT_CERTIFICATE:
                    report.note("certificate",
                                f"no {arguments.certificate} yet, comparison skipped")
                else:
                    report.check(f"--certificate {arguments.certificate} exists", False)
            card = Card(context, reader)
            try:
                run_identity_checks(card, report, expected)
            finally:
                card.close()

            say("\nrecovery")
            run_power_cycle(context, reader, report)

        if arguments.repeat:
            say("\nreliability")
            run_repeat(context, reader, report, arguments.repeat)

        if arguments.status:
            say("\nstatus")
            card = Card(context, reader)
            try:
                run_status(card, report)
            finally:
                card.close()

        if arguments.enroll:
            say("\nenrollment")
            card = Card(context, reader)
            try:
                run_enroll(card, report, args.placements)
            finally:
                card.close()

        if arguments.sign:
            say("\nsigning")
            card = Card(context, reader)
            try:
                run_sign(card, report)
            finally:
                card.close()

        if arguments.nonce:
            say("\nnonce")
            card = Card(context, reader)
            try:
                run_nonce(card, report)
            finally:
                card.close()

        if arguments.pinpad:
            say("\npin pad")
            card = Card(context, reader)
            try:
                run_pinpad(card, report)
            finally:
                card.close()

        if arguments.download_mode:
            say("\ndownload mode")
            card = Card(context, reader)
            try:
                run_download_mode(card, report)
            finally:
                card.close()

        say(f"\n{'FAILED' if report.failures else 'OK'} — {report.failures} failure(s)")
        emit("done", failures=report.failures)
        return 1 if report.failures else 0
    finally:
        pcsc.SCardReleaseContext(context)


if __name__ == "__main__":
    sys.exit(main())
