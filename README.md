# Local Encrypted Vault

A command-line password manager that securely stores credentials locally using symmetric encryption (AES-128 via Fernet) and PBKDF2 key derivation.

## Features
* Derives a strong encryption key from a user-provided master password using PBKDF2HMAC (SHA256, 100,000 iterations).
* Implements a unique, randomly generated cryptographic salt stored locally.
* Secures all data in a unified, encrypted binary file.

## Prerequisites
* Python 3.x
* `cryptography` library (`pip install cryptography`)

## Usage
**Adding a credential:**
`python vault.py -m myMasterPass -a GitHub mySecretPassword`

**Reading credentials:**
`python vault.py -m myMasterPass -r`
