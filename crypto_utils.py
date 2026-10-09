"""Versioned authenticated file encryption for Secure File Vault."""
from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from pathlib import PurePath

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

FORMAT_VERSION = 1
ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_PACKAGE_BYTES = MAX_FILE_BYTES + 16 * 1024
MAGIC = b"SFV1\n"


class VaultError(ValueError):
    """Expected invalid input, damaged package, or failed authentication."""


def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < 12:
        raise VaultError("Use a password with at least 12 characters.")


def validate_filename(filename: str) -> str:
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise VaultError("The package contains invalid filename metadata.")
    if filename in {".", ".."} or any(c in filename for c in ("/", "\\", "\0")):
        raise VaultError("Unsafe filename metadata was rejected.")
    if any(unicodedata.category(c).startswith("C") for c in filename):
        raise VaultError("The package contains invalid filename metadata.")
    if PurePath(filename).name != filename:
        raise VaultError("Unsafe filename metadata was rejected.")
    return filename


def derive_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    validate_password(password)
    if len(salt) != SALT_BYTES or not (100_000 <= iterations <= 2_000_000):
        raise VaultError("Invalid key derivation parameters.")
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object, field: str, expected: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) > MAX_PACKAGE_BYTES * 2:
        raise VaultError(f"Invalid {field} field in encrypted file.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise VaultError(f"Invalid {field} field in encrypted file.") from None
    if expected is not None and len(decoded) != expected:
        raise VaultError(f"Invalid {field} length in encrypted file.")
    return decoded


def encrypt_file(data: bytes, filename: str, password: str) -> bytes:
    if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
        raise VaultError("Files must be 100 MB or smaller.")
    name = validate_filename(filename)
    validate_password(password)
    salt, nonce = get_random_bytes(SALT_BYTES), get_random_bytes(NONCE_BYTES)
    key = derive_key(password, salt)
    aad = json.dumps({"version": FORMAT_VERSION, "filename": name, "iterations": ITERATIONS}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    package = {"version": FORMAT_VERSION, "filename": name, "iterations": ITERATIONS,
               "salt": _b64(salt), "nonce": _b64(nonce), "tag": _b64(tag), "ciphertext": _b64(ciphertext)}
    return MAGIC + json.dumps(package, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def parse_package(blob: bytes) -> dict:
    if not isinstance(blob, bytes) or len(blob) > MAX_PACKAGE_BYTES or not blob.startswith(MAGIC):
        raise VaultError("This is not a valid Secure File Vault package.")
    try:
        pkg = json.loads(blob[len(MAGIC):].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VaultError("The encrypted file is malformed or corrupted.") from None
    fields = {"version", "filename", "iterations", "salt", "nonce", "tag", "ciphertext"}
    if not isinstance(pkg, dict) or set(pkg) != fields:
        raise VaultError("The encrypted file is malformed or has unsupported fields.")
    if type(pkg["version"]) is not int or pkg["version"] != FORMAT_VERSION:
        raise VaultError("This encrypted file uses an unsupported format version.")
    validate_filename(pkg["filename"])
    if type(pkg["iterations"]) is not int or not 100_000 <= pkg["iterations"] <= 2_000_000:
        raise VaultError("Invalid key derivation parameters in encrypted file.")
    salt = _unb64(pkg["salt"], "salt", SALT_BYTES)
    nonce = _unb64(pkg["nonce"], "nonce", NONCE_BYTES)
    tag = _unb64(pkg["tag"], "authentication tag", TAG_BYTES)
    ciphertext = _unb64(pkg["ciphertext"], "ciphertext")
    if len(ciphertext) > MAX_FILE_BYTES:
        raise VaultError("The encrypted file exceeds the supported size limit.")
    return {**pkg, "_salt": salt, "_nonce": nonce, "_tag": tag, "_ciphertext": ciphertext}


def decrypt_file(blob: bytes, password: str) -> tuple[str, bytes]:
    validate_password(password)
    pkg = parse_package(blob)
    key = PBKDF2(password.encode("utf-8"), pkg["_salt"], dkLen=32, count=pkg["iterations"], hmac_hash_module=SHA256)
    aad = json.dumps({"version": pkg["version"], "filename": pkg["filename"], "iterations": pkg["iterations"]}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce=pkg["_nonce"], mac_len=TAG_BYTES)
    cipher.update(aad)
    try:
        plaintext = cipher.decrypt_and_verify(pkg["_ciphertext"], pkg["_tag"])
    except ValueError:
        raise VaultError("Authentication failed. Check the password or file integrity.") from None
    return pkg["filename"], plaintext


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"
