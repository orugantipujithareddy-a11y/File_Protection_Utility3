# File Protection Utility

A command-line Python utility for encrypting and decrypting local files using **AES-256-CBC**, **PBKDF2-HMAC-SHA256**, random salt/IV values, and **HMAC-SHA256** integrity verification.

## Features
- AES-256 symmetric file encryption
- PBKDF2-HMAC-SHA256 password-based key derivation
- Random 16-byte salt and IV for every encryption
- HMAC-SHA256 authentication/integrity protection
- Interactive password entry; passwords are not stored in the script
- Encrypt, decrypt, and verify CLI commands

## Project Structure
```text
file-protection-utility/
├── file_protection.py
├── README.md
├── requirements.txt
├── .gitignore
├── sample_input.txt
├── 01_encrypt_verify.png
├── 02_decrypt_hash.png
└── 03_tamper_detection.png
```

## Requirements
Python 3.9+ and the `cryptography` package.

```bash
pip install -r requirements.txt
```

## Usage
### Encrypt
```bash
python file_protection.py encrypt sample_input.txt sample_input.enc
```

### Verify integrity
```bash
python file_protection.py verify sample_input.enc
```

### Decrypt
```bash
python file_protection.py decrypt sample_input.enc recovered.txt
```

### Compare SHA-256 hashes
Windows PowerShell:
```powershell
Get-FileHash sample_input.txt -Algorithm SHA256
Get-FileHash recovered.txt -Algorithm SHA256
```
Linux/macOS:
```bash
sha256sum sample_input.txt recovered.txt
```

## Security Design
1. A fresh random salt is generated for every encryption.
2. PBKDF2-HMAC-SHA256 derives 64 bytes from the password.
3. The first 32 bytes are used as the AES-256 key; the next 32 bytes are used as the HMAC key.
4. PKCS7 padding is applied before AES-256-CBC encryption.
5. The encrypted file contains a header, salt, IV, ciphertext, and HMAC-SHA256 tag.
6. HMAC verification occurs before decrypted plaintext is written.

## Evidence
The included screenshots demonstrate successful encryption, integrity verification, decryption with matching SHA-256 hashes, and rejection of modified encrypted data.

**Do not commit real passwords, private files, or sensitive encrypted files to a public GitHub repository.**
