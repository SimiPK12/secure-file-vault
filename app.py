"""Secure File Vault — local Streamlit interface."""
from __future__ import annotations

import mimetypes
import html
import time

import streamlit as st

from crypto_utils import MAX_FILE_BYTES, VaultError, decrypt_file, encrypt_file, format_size

st.set_page_config(page_title="Secure File Vault", page_icon="🔐", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
:root { --navy:#071321; --panel:#0d1d30; --line:#20344d; --blue:#38a8ff; --green:#36d399; }
.stApp {background:radial-gradient(ellipse at 15% -10%,#102e4a 0%,#071321 45%); color:#edf5ff; font-family:system-ui,sans-serif}
h1,h2,h3 {font-family:system-ui,sans-serif!important; letter-spacing:-.03em}
.hero {padding:2.1rem 2.3rem;border:1px solid #24415d;border-radius:22px;background:linear-gradient(120deg,rgba(16,43,68,.96),rgba(10,25,42,.96)); margin:0 0 1.25rem}
.hero h1 {margin:0;color:#f4f9ff;font-size:2.5rem}.hero p {color:#a9c2dc;margin:.45rem 0 1.15rem;font-size:1.05rem}
.pill {display:inline-block;padding:.38rem .75rem;border:1px solid #294764;border-radius:99px;margin:0 .4rem .25rem 0;color:#cde3fa;background:#122941;font-size:.83rem}
.card {background:#0c1c2e;border:1px solid #20364f;border-radius:16px;padding:1.1rem 1.25rem;margin:.5rem 0 1rem}
.eyebrow {text-transform:uppercase;color:#80a6ca;font-size:.75rem;letter-spacing:.12em;font-weight:700}
.muted {color:#a9bfd5}.stButton>button[kind=primary],.stDownloadButton>button {border-radius:11px;min-height:2.8rem;font-weight:700}
[data-testid="stSidebar"] {background:#081726;border-right:1px solid #1c3249}
div[data-testid="stMetric"] {background:#0d1d30;border:1px solid #20364f;padding:1rem;border-radius:14px}
@media(max-width:700px){.hero{padding:1.3rem}.hero h1{font-size:1.9rem}}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<section class="hero">
  <div class="eyebrow">🔐 PRIVATE BY DESIGN · LOCAL PROCESSING</div>
  <h1>Secure File Vault</h1>
  <p>Protect your files with AES-256 encryption.</p>
  <span class="pill">◈ AES-256-GCM</span><span class="pill">♧ Password protected</span><span class="pill">✓ Integrity verified</span>
</section>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 🔐 Secure Vault")
    page = st.radio("Navigation", ["Home", "Encrypt File", "Decrypt File", "About Project"], label_visibility="collapsed")
    st.markdown("---")
    st.caption("Files are processed in memory. Credentials and keys are not retained.")


def file_card(upload, encrypted=False):
    if upload is None:
        st.markdown('<div class="card"><div class="eyebrow">Waiting for a file</div><p class="muted">Choose a file to see its details and continue.</p></div>', unsafe_allow_html=True)
        return
    name = upload.name
    ext = name.rsplit(".", 1)[-1].upper() if "." in name else "No extension"
    kind = "Secure File Vault package" if encrypted else (mimetypes.guess_type(name)[0] or "Unknown / binary file")
    st.markdown(f'<div class="card"><div class="eyebrow">Selected file</div><b>{html.escape(name)}</b><p class="muted">{html.escape(ext)} &nbsp;·&nbsp; {format_size(upload.size)} &nbsp;·&nbsp; {html.escape(kind)}</p></div>', unsafe_allow_html=True)


if page == "Home":
    st.subheader("Confidential file protection")
    st.write("Secure File Vault protects files using password-derived encryption and authenticated integrity checks. Encrypt files before storage or transfer, then restore them after successful authentication.")
    cols = st.columns(3)
    for col, title, body in zip(cols, ["01 · Encrypt", "02 · Transfer", "03 · Restore"], ["Select a file and define a strong password.", "Transfer the encrypted package and password separately.", "Authenticate the package and retrieve the original file."]):
        with col: st.markdown(f'<div class="card"><div class="eyebrow">{title}</div><p>{body}</p></div>', unsafe_allow_html=True)
    st.info("Select **Encrypt File** to create a protected package, or **Decrypt File** to authenticate and restore one. Maximum supported file size: 100 MB.")

elif page == "Encrypt File":
    st.subheader("Encrypt a file")
    st.write("Create an authenticated encrypted package for your file. Use a unique password of at least 12 characters.")
    upload = st.file_uploader("Select file", key="encrypt_upload", help="PDF, TXT, DOCX, images, ZIP, and other file formats are supported.")
    file_card(upload)
    reveal = st.checkbox("Show password", key="encrypt_reveal")
    password = st.text_input("Encryption password", type="default" if reveal else "password", key="encrypt_pw", help="Enter at least 12 characters. The password is not stored.")
    if upload and upload.size > MAX_FILE_BYTES: st.error("Files must be 100 MB or smaller.")
    if st.button("Encrypt file", type="primary", use_container_width=True, disabled=upload is None):
        if not password or len(password) < 12:
            st.error("Enter a password with at least 12 characters.")
        elif upload.size > MAX_FILE_BYTES:
            st.error("Files must be 100 MB or smaller.")
        else:
            progress = st.progress(0, text="Preparing secure encryption…")
            started = time.perf_counter()
            try:
                data = upload.getvalue()
                progress.progress(35, text="Deriving a key and encrypting…")
                package = encrypt_file(data, upload.name, password)
                elapsed = time.perf_counter() - started
                progress.progress(100, text="Encryption complete")
                st.session_state["encrypted_result"] = (package, upload.name + ".enc", elapsed)
            except VaultError as exc:
                progress.empty(); st.error(str(exc))
            except Exception:
                progress.empty(); st.error("Encryption could not be completed. Please retry with a valid file.")
    result = st.session_state.get("encrypted_result")
    if result:
        package, out_name, elapsed = result
        st.success("File encrypted successfully.")
        st.download_button("Download encrypted file", package, file_name=out_name, mime="application/octet-stream", type="primary", use_container_width=True)
        a,b,c = st.columns(3)
        a.metric("Encrypted package", format_size(len(package)))
        b.metric("Elapsed time", f"{elapsed:.2f} s")
        c.metric("Cipher", "AES-256-GCM")
        st.caption("Keep your password safe. The encrypted package cannot be recovered without it.")

elif page == "Decrypt File":
    st.subheader("Decrypt a file")
    st.write("Select a Secure File Vault `.enc` package. The original file is made available only after successful authentication.")
    upload = st.file_uploader("Select encrypted file (.enc)", type=["enc"], key="decrypt_upload")
    file_card(upload, encrypted=True)
    reveal = st.checkbox("Show password", key="decrypt_reveal")
    password = st.text_input("Decryption password", type="default" if reveal else "password", key="decrypt_pw")
    if st.button("Authenticate and decrypt", type="primary", use_container_width=True, disabled=upload is None):
        if not password or len(password) < 12:
            st.error("Enter the password used to encrypt this file (at least 12 characters).")
        else:
            with st.spinner("Verifying package and authenticating…"):
                try:
                    name, plaintext = decrypt_file(upload.getvalue(), password)
                    st.session_state["decrypted_result"] = (name, plaintext)
                except VaultError as exc:
                    st.session_state.pop("decrypted_result", None)
                    st.error(str(exc))
                except Exception:
                    st.session_state.pop("decrypted_result", None)
                    st.error("Decryption could not be completed. The package may be invalid or damaged.")
    result = st.session_state.get("decrypted_result")
    if result:
        name, plaintext = result
        st.success("Authentication successful. The file is ready to download.")
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        st.download_button("Download original file", plaintext, file_name=name, mime=mime, type="primary", use_container_width=True)
        st.caption(f"Verified original size: {format_size(len(plaintext))}")

elif page == "About Project":
    st.subheader("About Secure File Vault")
    st.markdown('<div class="card"><div class="eyebrow">Abstract</div><p>Secure File Vault is a file protection application that provides password-based encryption and authenticated decryption through a portable, versioned file format. It derives a 256-bit cryptographic key from a user-supplied password using PBKDF2-HMAC-SHA256 and encrypts file contents with AES-256 in Galois/Counter Mode (GCM). The package includes the cryptographic parameters and original filename metadata required for recovery. GCM authentication verifies the encrypted content and associated metadata before any plaintext is released, enabling detection of incorrect passwords and unauthorized modification.</p></div>', unsafe_allow_html=True)
    st.markdown("#### AES algorithm")
    st.write("The Advanced Encryption Standard (AES) is a symmetric block cipher standardized for protecting digital information. It transforms data in fixed-size 128-bit blocks using a secret key; AES-256 uses a 256-bit key. Secure File Vault uses AES in Galois/Counter Mode (GCM), which combines encryption with an authentication tag. The tag allows the application to verify that the encrypted contents and authenticated metadata have not been altered before returning the original file.")
    st.markdown("#### Objectives")
    st.markdown("- Protect file confidentiality using password-derived AES-256 keys.\n- Verify file integrity and authenticated metadata during decryption.\n- Provide a portable encrypted package and recover files with their original names and bytes.\n- Process files in memory without permanently saving uploaded or decrypted content.")
    st.markdown("#### Technologies")
    st.write("Python 3.11+, Streamlit, PyCryptodome, AES-256-GCM, PBKDF2-HMAC-SHA256, and pytest.")
    st.markdown("#### Processing workflow")
    st.write("Encryption: file selection → password validation → random salt and key derivation → AES-GCM encryption with a fresh nonce → authenticated package creation → encrypted file download. Decryption: package validation → key derivation from the supplied password and stored salt → GCM authentication → original file download after successful verification.")
    st.markdown("#### Operational considerations")
    st.write("The application supports files up to 100 MB. Recovery requires the original password; there is no password reset mechanism. Password strength and secure handling of both the password and encrypted package are important. As with any application, security also depends on the integrity of the host computer and its runtime environment.")
