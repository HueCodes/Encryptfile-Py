# Encryptfile-Py

A small, lightweight file encryption utility using AES-GCM and password-wrapped keys.

Features
- Generate a random AES-256 key and save it encrypted with a password (PBKDF2-HMAC-SHA256).
- Encrypt and decrypt files using AES-GCM (authenticated encryption).
- Minimal, dependency-based implementation using the `cryptography` library.

Quick start

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Generate a key (you will be prompted for a password unless you use `--password` or `--password-env`):

```bash
python encryption-tool.py genkey --keyfile key.enc
```

3. Encrypt a file:

```bash
python encryption-tool.py encrypt --input secret.txt --output secret.txt.enc --keyfile key.enc
```

4. Decrypt a file:

```bash
python encryption-tool.py decrypt --input secret.txt.enc --output secret.txt --keyfile key.enc
```

Notes on non-interactive usage
- For scripting and tests, `--password` (insecure) or `--password-env` (safer) are available. `--password` passes the password on the command line and is visible to other processes, so prefer `--password-env`.

Security notes
- The tool uses PBKDF2 with SHA-256 and 100k iterations by default. For high-security use, consider using Argon2.
- The key file format is: salt(16) || nonce(12) || ciphertext. Keep the key file protected.
- This project is a convenience tool and is not a drop-in replacement for a full secure key management solution.

Contributing
- Tests are run with `pytest` (see `tests/test_roundtrip.py`).
- License: MIT (see `LICENSE`).



