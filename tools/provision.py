#!/usr/bin/env python3
# Copyright (c) 2026 Maksym Bardakh. All rights reserved.
# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Source-available under LICENSE.md with the permissions in LICENSING.md.

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_pem_private_key,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


SMART_CARD_LOGON_OID = ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")
CERTIFICATE_TAG = bytes.fromhex("5FC105")
GENERATE_KEY_9A = bytes.fromhex("0047009A05AC0380011100")
KEY_MANAGEMENT_CERTIFICATE_TAG = bytes.fromhex("5FC10B")
GENERATE_KEY_9D = bytes.fromhex("0047009D05AC0380011100")
AUTHORITY_DAYS = 3650
CERTIFICATE_DAYS = 825


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision a connected DeskID board: it generates its own "
        "private key and this host only issues a certificate for it."
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path(".pio/provisioning"),
    )
    parser.add_argument(
        "--reader",
        default="DeskID",
        help="Substring of the PC/SC reader name to provision.",
    )
    parser.add_argument(
        "--ca-certificate",
        type=Path,
        help="Issuing authority certificate, default deskid-ca.crt in the output directory.",
    )
    parser.add_argument(
        "--ca-key",
        type=Path,
        help="Issuing authority private key, default deskid-ca.key in the output directory.",
    )
    parser.add_argument(
        "--create-ca",
        action="store_true",
        help="Create the self-signed issuing authority before provisioning.",
    )
    parser.add_argument(
        "--key-management",
        action="store_true",
        help="Add the slot 9D key and its certificate to a board that already "
        "has its identity. Slot 9A is not touched, so a paired Mac stays paired.",
    )
    parser.add_argument(
        "--common-name",
        default="DeskID Device",
        help="Subject common name of the issued certificate.",
    )
    # Provisioning on the board is the only mode left; invocations that still
    # pass the old flag keep working.
    parser.add_argument("--on-device", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def load_certificate(path: Path) -> x509.Certificate:
    encoded = path.read_bytes()
    if encoded.startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(encoded)
    return x509.load_der_x509_certificate(encoded)


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("private-key permissions must not grant group or other access")
    encoded = path.read_bytes()
    try:
        key = (
            load_pem_private_key(encoded, password=None)
            if encoded.startswith(b"-----BEGIN")
            else load_der_private_key(encoded, password=None)
        )
    except TypeError as error:
        raise ValueError(
            "private key must be unencrypted during this isolated provisioning step"
        ) from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("private key must use the P-256 (prime256v1) curve")
    return key


def validate_identity(certificate: x509.Certificate) -> None:
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("certificate public key must use P-256")

    now = datetime.now(timezone.utc)
    if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
        raise ValueError("certificate is not currently valid")

    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as error:
        raise ValueError("certificate must include a Key Usage extension") from error
    if not key_usage.digital_signature:
        raise ValueError("certificate Key Usage must allow digital signatures")

    try:
        extended_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound as error:
        raise ValueError("certificate must include an Extended Key Usage extension") from error
    if (
        ExtendedKeyUsageOID.CLIENT_AUTH not in extended_usage
        and SMART_CARD_LOGON_OID not in extended_usage
    ):
        raise ValueError(
            "certificate Extended Key Usage must include clientAuth or smart-card logon"
        )


def prepare_output_directory(output_directory: Path) -> None:
    output_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_directory, 0o700)


def encode_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, value >> 8, value & 0xFF])


def certificate_object(certificate_der: bytes) -> bytes:
    content = (
        b"\x70"
        + encode_length(len(certificate_der))
        + certificate_der
        + bytes.fromhex("710100FE00")
    )
    return b"\x53" + encode_length(len(content)) + content


def put_data_apdu(stored_object: bytes, tag: bytes = CERTIFICATE_TAG) -> bytes:
    body = b"\x5c" + encode_length(len(tag)) + tag + stored_object
    return (
        bytes([0x00, 0xDB, 0x3F, 0xFF, 0x00, len(body) >> 8, len(body) & 0xFF]) + body
    )


def create_certificate_authority(certificate_path: Path, key_path: Path) -> None:
    for path in (certificate_path, key_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite {path}")

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "DeskID Provisioning CA")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=AUTHORITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    key_path.touch(mode=0o600)
    key_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    certificate_path.write_bytes(certificate.public_bytes(Encoding.PEM))


def issue_certificate(
    public_key: ec.EllipticCurvePublicKey,
    authority: x509.Certificate,
    authority_key: ec.EllipticCurvePrivateKey,
    common_name: str,
    key_agreement: bool = False,
) -> x509.Certificate:
    """The identity certificate signs; the key management one only agrees keys."""
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        .issuer_name(authority.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CERTIFICATE_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not key_agreement,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=key_agreement,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()),
            critical=False,
        )
    )
    if not key_agreement:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, SMART_CARD_LOGON_OID]
            ),
            critical=False,
        )
    return builder.sign(authority_key, hashes.SHA256())


def provision_key_management(card, smoke, authority, authority_key, hint):
    """Slot 9D for a board that has its identity: key, certificate, proof.

    macOS wraps the login keychain password to this key when the card is
    paired, and without it asks for that password at every smart card unlock.
    """
    stored, status, _ = smoke.get_data(card, CERTIFICATE_TAG)
    der = (
        smoke.read_tlv(smoke.read_tlv(stored).get(0x53, b"")).get(0x70, b"")
        if status == smoke.SW_OK
        else b""
    )
    if not der:
        raise ValueError("the board has no identity certificate — provision it first")
    identity = x509.load_der_x509_certificate(der)
    try:
        authority.public_key().verify(
            identity.signature,
            identity.tbs_certificate_bytes,
            ec.ECDSA(identity.signature_hash_algorithm),
        )
    except InvalidSignature as error:
        raise ValueError(
            "this authority did not issue the board's identity certificate"
        ) from error
    common_name = identity.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    hint("generating the key management key")
    data, status, elapsed = card.send(GENERATE_KEY_9D)
    if status != smoke.SW_OK:
        raise ValueError(f"GENERATE ASYMMETRIC KEY PAIR failed with SW {status:04X}")
    point = smoke.read_tlv(smoke.read_tlv(data[1:]).get(0x49, b"")).get(0x86, b"")
    if len(point) != 65:
        raise ValueError(f"unexpected key generation response: {data.hex().upper()}")
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    print(f"device generated a P-256 key management key in {elapsed:.1f} s")

    certificate = issue_certificate(
        public_key, authority, authority_key, common_name, key_agreement=True
    )
    stored_object = certificate_object(certificate.public_bytes(Encoding.DER))
    hint("storing the certificate")
    _, status, _ = card.send(put_data_apdu(stored_object, KEY_MANAGEMENT_CERTIFICATE_TAG))
    if status != smoke.SW_OK:
        raise ValueError(f"PUT DATA failed with SW {status:04X}")
    read_back, status, _ = smoke.get_data(card, KEY_MANAGEMENT_CERTIFICATE_TAG)
    if status != smoke.SW_OK or read_back != stored_object:
        raise ValueError("the certificate read back from the device differs")

    # The board and this host each derive the secret; equal secrets mean the
    # private half of the certified key is on the board.
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    body = bytes([0x7C, 0x45, 0x82, 0x00, 0x85, 0x41]) + ephemeral.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    hint("proving the key is on-device")
    data, status, elapsed = card.send(
        bytes([0x00, 0x87, 0x11, 0x9D, len(body)]) + body + b"\x00"
    )
    if status != smoke.SW_OK:
        raise ValueError(f"GENERAL AUTHENTICATE failed with SW {status:04X}")
    secret = smoke.read_tlv(smoke.read_tlv(data).get(0x7C, b"")).get(0x82, b"")
    if secret != ephemeral.exchange(ec.ECDH(), public_key):
        raise ValueError("the device's shared secret does not match the issued certificate")
    print(f"device agreed a key with a random peer in {elapsed:.1f} s")
    return certificate


def provision_on_device(arguments: argparse.Namespace) -> int:
    # Imported here so --help never needs PCSC.framework.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import hw_smoke_test as smoke

    prepare_output_directory(arguments.output_directory)
    authority_path = (
        arguments.ca_certificate or arguments.output_directory / "deskid-ca.crt"
    )
    authority_key_path = (
        arguments.ca_key or arguments.output_directory / "deskid-ca.key"
    )
    if arguments.create_ca:
        create_certificate_authority(authority_path, authority_key_path)
        print(f"certificate authority: {authority_path}")
    elif not (authority_path.exists() and authority_key_path.exists()):
        raise ValueError(
            f"no issuing authority at {authority_path} — pass --create-ca to make one"
        )
    authority = load_certificate(authority_path)
    authority_key = load_private_key(authority_key_path)

    context = ctypes.c_int32(0)
    smoke.check(
        "SCardEstablishContext",
        smoke.pcsc.SCardEstablishContext(
            smoke.SCARD_SCOPE_SYSTEM, None, None, ctypes.byref(context)
        ),
    )
    try:
        readers = [
            name for name in smoke.list_readers(context) if arguments.reader in name
        ]
        if not readers:
            raise ValueError(
                f"no reader matching {arguments.reader!r} — is the board plugged in?"
            )
        card = smoke.Card(context, readers[0])
        try:
            _, status, _ = card.send(smoke.SELECT_PIV)
            if status != smoke.SW_OK:
                raise ValueError(f"SELECT PIV failed with SW {status:04X}")

            fields = smoke.status_object(card)
            if not fields:
                raise ValueError("the board did not return its status object (5FFF01)")
            # A board holding no credential answers every step below without a
            # fingerprint, so the hints would be noise on a factory line.
            gated = smoke.status_number(fields, 0x08) != 0
            print(f"board: {'provisioned, re-provisioning it' if gated else 'blank'}")

            def hint(action: str) -> None:
                if gated:
                    print(f"touch the sensor if one is attached — {action}")

            if arguments.key_management:
                certificate = provision_key_management(
                    card, smoke, authority, authority_key, hint
                )
                certificate_path = (
                    arguments.output_directory / "deskid-key-management.crt"
                )
                certificate_path.write_bytes(certificate.public_bytes(Encoding.PEM))
                print(f"key management certificate: {certificate_path}")
                return 0

            hint("generating the device key")
            data, status, elapsed = card.send(GENERATE_KEY_9A)
            if status != smoke.SW_OK:
                raise ValueError(f"GENERATE ASYMMETRIC KEY PAIR failed with SW {status:04X}")
            # 7F 49 is a two-byte tag; dropping the first byte leaves a
            # single-byte-tag TLV that read_tlv can walk.
            point = smoke.read_tlv(smoke.read_tlv(data[1:]).get(0x49, b"")).get(
                0x86, b""
            )
            if len(point) != 65:
                raise ValueError(f"unexpected key generation response: {data.hex().upper()}")
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), point
            )
            print(f"device generated a P-256 key pair in {elapsed:.1f} s")

            certificate = issue_certificate(
                public_key, authority, authority_key, arguments.common_name
            )
            validate_identity(certificate)
            stored_object = certificate_object(certificate.public_bytes(Encoding.DER))

            hint("storing the certificate")
            _, status, _ = card.send(put_data_apdu(stored_object))
            if status != smoke.SW_OK:
                raise ValueError(f"PUT DATA failed with SW {status:04X}")

            read_back, status, _ = smoke.get_data(card, CERTIFICATE_TAG)
            if status != smoke.SW_OK or read_back != stored_object:
                raise ValueError("the certificate read back from the device differs")

            digest = hashlib.sha256(os.urandom(32)).digest()
            hint("proving the key is on-device")
            data, status, elapsed = card.send(smoke.general_authenticate(digest))
            if status != smoke.SW_OK:
                raise ValueError(f"GENERAL AUTHENTICATE failed with SW {status:04X}")
            signature = smoke.read_tlv(smoke.read_tlv(data).get(0x7C, b"")).get(
                0x82, b""
            )
            try:
                public_key.verify(
                    signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                )
            except InvalidSignature as error:
                raise ValueError(
                    "the device signature does not match the issued certificate"
                ) from error
            print(f"device signed a random challenge in {elapsed:.1f} s")
        finally:
            card.close()
    finally:
        smoke.pcsc.SCardReleaseContext(context)

    certificate_path = arguments.output_directory / "deskid-device.crt"
    certificate_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    print(f"device certificate: {certificate_path}")
    print("No device private key was written: no copy of it exists on this host.")
    return 0


def main() -> int:
    try:
        return provision_on_device(parse_arguments())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"provisioning failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())