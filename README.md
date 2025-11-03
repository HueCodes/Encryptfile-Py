# Encryptfile-Py

[![CI](https://github.com/HueCodes/Encryptfile-Py/actions/workflows/ci.yml/badge.svg)](https://github.com/HueCodes/Encryptfile-Py/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python Versions](https://img.shields.io/badge/python-3.11%2C3.12-blue.svg)](#)

A small, lightweight file encryption utility using AES-GCM and password-wrapped keys.

Why this project
- Small and dependency-light tool to encrypt/decrypt files with AES-GCM and to manage an encrypted key file protected by a password-derived key.
- Useful for ad-hoc secure backups and simple automation where a full KMS is not required.

Features
- Generate a random AES-256 key and save it encrypted with a password (PBKDF2-HMAC-SHA256).
- Encrypt and decrypt files using AES-GCM (authenticated encryption).
- Small CLI and a testable library-style layout.

Quick start

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Generate a key (interactive):

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

Non-interactive / scripting
- For automated scripts or tests you can pass a password non-interactively (note: passing secrets on the command line is insecure and visible to other processes):

```bash
# less secure (visible in process table):
python encryption-tool.py genkey --password "hunter2" --keyfile key.enc

# safer: read password from an environment variable
export ENC_PASS="hunter2"
python encryption-tool.py encrypt --input a.txt --output a.txt.enc --keyfile key.enc --password-env ENC_PASS
```

Security notes
- Default KDF: PBKDF2-HMAC-SHA256 with 100_000 iterations. For higher-resistance to brute force, consider Argon2.
- Key file layout: salt (16 bytes) || nonce (12 bytes) || ciphertext.
- AES-GCM provides authenticity — decryption will fail if the ciphertext or nonce is tampered with.
- Keep `key.enc` with restrictive file permissions (e.g., chmod 600) and do not commit it to source control.

Testing
- Tests are run with `pytest` (see `tests/test_roundtrip.py`). The repository includes a small round-trip test that generates a key, encrypts a random binary file, then decrypts it and asserts equality.

Install from GitHub (optional)

```bash
pip install git+https://github.com/HueCodes/Encryptfile-Py.git
```

Contributing
- Open issues or PRs on GitHub. If you add features that change the key file format, include a migration path and increase the format version.

License
- MIT — see `LICENSE`.
