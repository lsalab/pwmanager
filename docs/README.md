# Documentation

This directory contains additional documentation for the password manager.

## Available Documentation

- [TESTING.md](TESTING.md) - Complete guide to running and understanding the test suite

## Project Features

The password manager includes:

- **Multiple Cipher Modes**: GCM (default for new datastores), CBC (legacy support only)
- **Automatic Legacy Migration**: Old datastores without cryptographic parameters are automatically updated
- **PBKDF2 Key Derivation**: Secure key derivation with 100,000 iterations and unique salt per datastore
- **Cryptographic Flexibility**: Each datastore specifies its cipher and mode
- **Authenticated Encryption**: GCM mode provides authentication tags for tamper detection
- **Backward Compatibility**: Legacy CBC datastores continue to work seamlessly

