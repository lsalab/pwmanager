# pwmanager

A simple Tk-based password manager with AES-256-GCM encryption.

## Features

- **Secure Password Storage**: Passwords are encrypted using AES-256-GCM
- **Authenticated Encryption**: GCM (Galois/Counter Mode) provides authenticated encryption with tamper detection
- **PBKDF2 Key Derivation**: Secure key derivation with 100,000 iterations and unique salt
- **Graphical User Interface**: Easy-to-use Tkinter-based GUI
- **Terminal Mode**: Command-line interface for scriptable access
- **Challenge-Based Authentication**: Passphrase verification without storing keys
- **Cryptographic Parameters**: Datastores include cipher mode, salt, and iteration count

## Usage

### GUI Mode

```bash
python3 pwmanager.py
```

### Terminal Mode

```bash
python3 pwmanager.py --no-gui
```

### Terminal Mode with Search

```bash
python3 pwmanager.py --no-gui --search github
```

### Custom Datastore Location

```bash
python3 pwmanager.py -s /path/to/datastore.pws
```

## How It Works

- **Encryption Key**: Derived from passphrase using PBKDF2 with salt and 100,000 iterations
- **Challenge System**: Uses PBKDF2 with one's complement of passphrase for verification
- **Password Entries**: Each entry is encrypted separately with its own IV
- **Datastore Format**: JSON file containing cryptographic parameters (salt, iterations, cipher mode), challenge, and encrypted entries

## Cryptographic Details

### Datastores
- **Cipher**: AES-256
- **Mode**: GCM (Galois/Counter Mode) with authentication tags
- **Key Derivation**: PBKDF2 with 100,000 iterations and 16-byte salt

All datastores use GCM mode for authenticated encryption, providing both confidentiality and integrity protection.

## Dependencies

+ Python >= 3.8
+ PyCryptodome or PyCryptodomex
+ Tkinter (usually included with Python)

Install dependencies:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install pycryptodome
```

## Documentation

- [Testing Guide](docs/TESTING.md) - How to run the test suite

## Security Notes

- GCM mode provides authenticated encryption, protecting against tampering
- Each password entry uses a unique nonce (IV)
- The passphrase is never stored - only the encrypted challenge
- PBKDF2 key derivation uses 100,000 iterations with unique salt per datastore
