import base64
import json

import pytest

from crypto_utils import MAGIC, VaultError, decrypt_file, encrypt_file, parse_package


def mutate(blob, **changes):
    pkg = json.loads(blob[len(MAGIC):])
    pkg.update(changes)
    return MAGIC + json.dumps(pkg, separators=(",", ":")).encode()


@pytest.mark.parametrize("data,name", [(b"hello secure world", "notes.txt"), (bytes(range(256)) * 40, "photo.png")])
def test_roundtrip(data, name):
    recovered_name, recovered = decrypt_file(encrypt_file(data, name, "correct horse battery staple"), "correct horse battery staple")
    assert recovered == data
    assert recovered_name == name


def test_wrong_password_rejected():
    with pytest.raises(VaultError, match="Authentication failed"):
        decrypt_file(encrypt_file(b"x", "a.txt", "correct horse battery staple"), "wrong password here")


def test_modified_ciphertext_rejected():
    blob = encrypt_file(b"some meaningful data", "a.txt", "correct horse battery staple")
    pkg = json.loads(blob[len(MAGIC):])
    raw = bytearray(base64.b64decode(pkg["ciphertext"]))
    raw[0] ^= 1
    with pytest.raises(VaultError, match="Authentication failed"):
        decrypt_file(mutate(blob, ciphertext=base64.b64encode(raw).decode()), "correct horse battery staple")


def test_modified_tag_rejected():
    blob = encrypt_file(b"some meaningful data", "a.txt", "correct horse battery staple")
    pkg = json.loads(blob[len(MAGIC):])
    raw = bytearray(base64.b64decode(pkg["tag"]))
    raw[0] ^= 1
    with pytest.raises(VaultError, match="Authentication failed"):
        decrypt_file(mutate(blob, tag=base64.b64encode(raw).decode()), "correct horse battery staple")


def test_malformed_package_rejected():
    with pytest.raises(VaultError):
        parse_package(b"not a package")
    with pytest.raises(VaultError):
        parse_package(MAGIC + b"{")


def test_unsupported_version_rejected():
    blob = encrypt_file(b"x", "a.txt", "correct horse battery staple")
    with pytest.raises(VaultError, match="unsupported format"):
        parse_package(mutate(blob, version=999))


def test_randomness_makes_repeated_outputs_different():
    a = encrypt_file(b"same plaintext", "a.txt", "correct horse battery staple")
    b = encrypt_file(b"same plaintext", "a.txt", "correct horse battery staple")
    assert a != b


@pytest.mark.parametrize("filename", ["../secret.txt", "folder/file.txt", "..", "bad\\name", "bad\x00name"])
def test_unsafe_filename_rejected(filename):
    with pytest.raises(VaultError):
        encrypt_file(b"data", filename, "correct horse battery staple")


def test_tampered_filename_rejected():
    blob = encrypt_file(b"data", "good.txt", "correct horse battery staple")
    with pytest.raises(VaultError):
        decrypt_file(mutate(blob, filename="../outside.txt"), "correct horse battery staple")


def test_short_password_rejected():
    with pytest.raises(VaultError, match="12 characters"):
        encrypt_file(b"x", "a.txt", "short")
