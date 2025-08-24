import os
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
import base64
import argparse

class EncryptionTool:
    """A lightweight encryption tool for file encryption/decryption with key management."""
    
    def __init__(self, key_file="key.enc"):
        self.key_file = key_file
        self.key_length = 32  # AES-256 requires 32-byte keys
        self.salt_length = 16  # Salt for key derivation
        self.iterations = 100_000  # PBKDF2 iterations

    def derive_key(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """Derive an encryption key from a password using PBKDF2HMAC."""
        if not salt:
            salt = os.urandom(self.salt_length)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=self.iterations
        )
        key = kdf.derive(password.encode())
        return key, salt

    def generate_key(self) -> bytes:
        """Generate a random AES key."""
        return os.urandom(self.key_length)

    def save_key(self, key: bytes, password: str) -> None:
        """Save an AES key encrypted with a password-derived key."""
        try:
            derived_key, salt = self.derive_key(password)
            aesgcm = AESGCM(derived_key)
            nonce = os.urandom(12)  # GCM nonce (12 bytes recommended)
            encrypted_key = aesgcm.encrypt(nonce, key, None)
            with open(self.key_file, "wb") as f:
                f.write(salt + nonce + encrypted_key)
        except Exception as e:
            raise ValueError(f"Failed to save key: {str(e)}")

    def load_key(self, password: str) -> bytes:
        """Load and decrypt the AES key using the password."""
        try:
            with open(self.key_file, "rb") as f:
                data = f.read()
            salt, nonce, encrypted_key = (
                data[:self.salt_length],
                data[self.salt_length:self.salt_length + 12],
                data[self.salt_length + 12:]
            )
            derived_key, _ = self.derive_key(password, salt)
            aesgcm = AESGCM(derived_key)
            return aesgcm.decrypt(nonce, encrypted_key, None)
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file '{self.key_file}' not found.")
        except InvalidKey:
            raise ValueError("Incorrect password or corrupted key file.")
        except Exception as e:
            raise ValueError(f"Failed to load key: {str(e)}")

    def encrypt_file(self, input_file: str, output_file: str, key: bytes) -> None:
        """Encrypt a file using AES-GCM."""
        try:
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            with open(input_file, "rb") as f_in:
                data = f_in.read()
            encrypted_data = aesgcm.encrypt(nonce, data, None)
            with open(output_file, "wb") as f_out:
                f_out.write(nonce + encrypted_data)
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file '{input_file}' not found.")
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_file(self, input_file: str, output_file: str, key: bytes) -> None:
        """Decrypt a file using AES-GCM."""
        try:
            with open(input_file, "rb") as f_in:
                data = f_in.read()
            nonce, ciphertext = data[:12], data[12:]
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            with open(output_file, "wb") as f_out:
                f_out.write(decrypted_data)
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file '{input_file}' not found.")
        except InvalidKey:
            raise ValueError("Incorrect key or corrupted file.")
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Lightweight file encryption tool.")
    parser.add_argument("action", choices=["genkey", "encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("--input", help="Input file path (for encrypt/decrypt)")
    parser.add_argument("--output", help="Output file path (for encrypt/decrypt)")
    args = parser.parse_args()

    tool = EncryptionTool()
    try:
        if args.action == "genkey":
            password = getpass.getpass("Enter password to encrypt the key: ")
            key = tool.generate_key()
            tool.save_key(key, password)
            print(f"Key generated and saved to '{tool.key_file}'.")
        elif args.action in ["encrypt", "decrypt"]:
            if not args.input or not args.output:
                raise ValueError("Both --input and --output are required for encrypt/decrypt.")
            password = getpass.getpass("Enter password to load the key: ")
            key = tool.load_key(password)
            if args.action == "encrypt":
                tool.encrypt_file(args.input, args.output, key)
                print(f"File encrypted to '{args.output}'.")
            else:
                tool.decrypt_file(args.input, args.output, key)
                print(f"File decrypted to '{args.output}'.")
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()