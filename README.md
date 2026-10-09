# Secure File Vault

**Secure File Vault — Secure File Encryption and Decryption System** is a local educational application for encrypting files with password-derived AES-256-GCM keys. Files are handled in memory and exported as portable `.enc` packages.

## Abstract

The project demonstrates confidentiality and integrity together: PBKDF2-HMAC-SHA256 derives a 256-bit key from a user password, while AES-GCM encrypts the file and authenticates both its bytes and relevant metadata. Decryption verifies the authentication tag before returning plaintext.

## Objectives and features

- Encrypt common file formats and binary data into a versioned `.enc` package.
- Decrypt only after successful password and integrity verification.
- Explain the cryptographic workflow through a responsive Streamlit interface.
- Avoid writing uploaded or recovered file contents to server disk.
- Provide clear validation, error messages, and automated cryptographic tests.

## Architecture

- `app.py` renders navigation, upload/download controls, file details, feedback, and educational pages.
- `crypto_utils.py` contains password validation, PBKDF2 key derivation, AES-GCM encryption/decryption, filename checks, package parsing, and size formatting.
- `tests/test_crypto.py` covers round trips, binary data, authentication failures, malformed packages, versions, randomized output, and unsafe names.

The package begins with `SFV1\n` followed by UTF-8 JSON with version, original filename, PBKDF2 iteration count, salt, nonce, tag, and ciphertext (binary fields use Base64). Filename and KDF parameters are canonicalized as AES-GCM additional authenticated data. Version 1 uses 16-byte random salts, 12-byte random nonces, 16-byte tags, and 600,000 PBKDF2-HMAC-SHA256 iterations. Iteration values are bounded while parsing to avoid abusive input. Maximum plaintext size is 100 MiB.

## Requirements

Python 3.11 or newer. Dependencies are Streamlit, PyCryptodome, and pytest. After installation, the application works without an internet connection; styling uses local system fonts.

## Setup

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Run the tests in another terminal with the virtual environment active:

```powershell
python -m pytest -q
```

### macOS / Linux

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Run tests with `python -m pytest -q`.

## Usage

1. Open **Encrypt File**, select a file up to 100 MB, and enter a unique password of at least 12 characters.
2. Download the generated `<original filename>.enc` package.
3. Move/share the package independently from the password.
4. Open **Decrypt File**, select the package, enter the password, authenticate, then download the recovered original filename and bytes.

No account or remote service is required. The application does not persist files to its own filesystem. Streamlit holds uploaded values and session download results in process memory while the session is active.

## Security concepts

- **Symmetric encryption**: the same secret key encrypts and decrypts.
- **Plaintext / ciphertext**: readable input becomes encrypted bytes.
- **Key derivation**: PBKDF2 deliberately repeats HMAC-SHA256 so password guessing costs more work.
- **Salt**: random, non-secret data that makes the derived key unique for each encryption.
- **Nonce**: random per-encryption GCM input; reuse with the same key is unsafe.
- **Authentication tag**: verifies password correctness and that the encrypted bytes/metadata have not changed. The library performs verification before plaintext is returned.
- **Tamper detection**: filename, version, and KDF settings are authenticated as additional data.

## Limitations and responsible use

This is an educational demonstration, not a production key-management service. Password strength determines practical resistance to guessing. **If you lose the password, the file cannot normally be recovered.** There is no password reset or recovery mechanism. Users should keep a secure backup of both the encrypted package and its password, stored separately. A compromised computer or browser session may expose plaintext or passwords in memory. The app limits files to 100 MiB and accepts format version 1 only. Have cryptographic software independently reviewed before relying on it for high-value data.
