#!/usr/bin/env python3
"""
PyLock - A simple AES file encryptor/decryptor.

Usage:
  Encrypt a file:
    python pylock.py encrypt --infile <input-file> --outfile <output-file> --password <passphrase>

  Decrypt a file:
    python pylock.py decrypt --infile <input-file> --outfile <output-file> --password <passphrase>
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """
    Derive a 256-bit key using PBKDF2 HMAC (SHA256).
    """
    kdf_func = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf_func.derive(password.encode())


def encrypt_file(infile: str, outfile: str, password: str):
    # Generate a random salt
    salt = os.urandom(16)
    # Derive the encryption key from password + salt
    key = derive_key(password, salt)

    # Generate a random 96-bit nonce for AES GCM
    nonce = os.urandom(12)

    # Create AES-GCM cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Read input file in chunks
    chunk_size = 64 * 1024
    with open(infile, 'rb') as fin, open(outfile, 'wb') as fout:
        # Write the salt and nonce first so we can use them during decryption
        fout.write(salt)
        fout.write(nonce)

        # Read and encrypt in chunks
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            fout.write(encrypted_chunk)

        # Finalize encryption
        final_data = encryptor.finalize()
        fout.write(final_data)

        # Write GCM tag at the end
        fout.write(encryptor.tag)


def decrypt_file(infile: str, outfile: str, password: str):
    with open(infile, 'rb') as fin:
        # Read salt and nonce from the beginning
        salt = fin.read(16)
        nonce = fin.read(12)

        # Derive the same key using the password + salt
        key = derive_key(password, salt)

        # The remaining data (except last 16 bytes) is the ciphertext
        file_data = fin.read()
        # The last 16 bytes are the GCM authentication tag
        tag = file_data[-16:]
        ciphertext = file_data[:-16]

        # Create AES-GCM cipher for decryption
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # Decrypt
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Write plaintext to outfile
    with open(outfile, 'wb') as fout:
        fout.write(decrypted_data)


def main():
    parser = argparse.ArgumentParser(description="PyLock - Simple AES encrypt/decrypt tool")
    subparsers = parser.add_subparsers(dest="command", help="encrypt or decrypt")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("--infile", required=True, help="Path to the input file")
    encrypt_parser.add_argument("--outfile", required=True, help="Path to the output file")
    encrypt_parser.add_argument("--password", required=True, help="Passphrase")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("--infile", required=True, help="Path to the encrypted file")
    decrypt_parser.add_argument("--outfile", required=True, help="Path to the output file")
    decrypt_parser.add_argument("--password", required=True, help="Passphrase")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "encrypt":
        encrypt_file(args.infile, args.outfile, args.password)
        print(f"File '{args.infile}' encrypted to '{args.outfile}'.")
    elif args.command == "decrypt":
        decrypt_file(args.infile, args.outfile, args.password)
        print(f"File '{args.infile}' decrypted to '{args.outfile}'.")

if __name__ == "__main__":
    main()
