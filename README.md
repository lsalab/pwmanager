# pwmanager

A simple Tk-based password manager with support for multiple cryptographic modes.

## Features

- **Secure Password Storage**: Passwords are encrypted using AES-256
- **Multiple Cipher Modes**: 
  - Default: GCM (Galois/Counter Mode) - Authenticated encryption (most secure)
  - Legacy: CBC (Cipher Block Chaining) - Backward compatibility
- **Automatic Migration**: Legacy CBC datastores are automatically detected and migrated
- **Graphical User Interface**: Easy-to-use Tkinter-based GUI
- **Terminal Mode**: Command-line interface for scriptable access
- **Challenge-Based Authentication**: Passphrase verification without storing keys
- **Cryptographic Parameters**: Datastores include cipher and mode information for flexibility

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

- **Encryption Key**: Derived from passphrase using SHA-256
- **Challenge System**: Uses one's complement of passphrase for verification
- **Password Entries**: Each entry is encrypted separately with its own IV
- **Datastore Format**: JSON file containing cryptographic parameters, challenge, and encrypted entries

## Cryptographic Details

### New Datastores
- **Cipher**: AES-256
- **Mode**: GCM (with authentication tags)
- **Key Derivation**: SHA-256 of passphrase

### Legacy Datastores
- **Cipher**: AES-256
- **Mode**: CBC (automatically migrated to include parameters)
- **Backward Compatible**: Old datastores continue to work

### Supported Modes
The system supports two secure AES modes:
- **GCM**: Galois/Counter Mode - Authenticated encryption (default for new datastores)
- **CBC**: Cipher Block Chaining - Legacy mode (for backward compatibility with existing datastores)

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
- Each password entry uses a unique IV (Initialization Vector)
- The passphrase is never stored - only the encrypted challenge
- Legacy CBC mode is supported for backward compatibility but GCM is recommended for new datastores
