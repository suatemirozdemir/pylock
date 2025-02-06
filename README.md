# PyLock

PyLock is a simple command-line tool to encrypt and decrypt files using AES in GCM mode.

## Features
- Symmetric encryption using a passphrase
- Uses `PBKDF2HMAC` to derive strong encryption keys
- Chunked file reading for efficiency
- Quick & easy usage

## Installation
1. Clone this repository.
2. (Optional) Create and activate a Python virtual environment.
3. Install requirements:
   ```bash
   pip install -r requirements.txt

## Usage
- Encrypt a file: 
    python pylock.py encrypt --infile my_file.txt --outfile my_file.txt.enc --password secret123
- Decrypt a file: 
    python pylock.py decrypt --infile my_file.txt.enc --outfile decrypted.txt --password secret123
