import os
import sys
import tempfile
import subprocess


def run(cmd, **kwargs):
    print("RUN:", cmd)
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def test_encrypt_decrypt_roundtrip(tmp_path):
    # Paths
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    script = os.path.join(repo_root, "encryption-tool.py")

    password = "testpassword"
    keyfile = os.path.join(tmp_path, "key.enc")
    input_file = os.path.join(tmp_path, "input.bin")
    encrypted_file = os.path.join(tmp_path, "input.bin.enc")
    decrypted_file = os.path.join(tmp_path, "input.dec.bin")

    # Write some binary data
    data = os.urandom(1024)
    with open(input_file, "wb") as f:
        f.write(data)

    # Generate key non-interactively
    run([sys.executable, script, "genkey", "--password", password, "--keyfile", keyfile])

    # Encrypt
    run([sys.executable, script, "encrypt", "--input", input_file, "--output", encrypted_file, "--keyfile", keyfile, "--password", password])

    # Decrypt
    run([sys.executable, script, "decrypt", "--input", encrypted_file, "--output", decrypted_file, "--keyfile", keyfile, "--password", password])

    # Verify
    with open(decrypted_file, "rb") as f:
        out = f.read()
    assert out == data
