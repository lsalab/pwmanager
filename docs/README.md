# Documentation

This directory contains additional documentation for the password manager.

## Available Documentation

- [TESTING.md](TESTING.md) - Complete guide to running and understanding the test suite

## Project Features

The password manager includes:

- **AES-256-GCM Encryption**: All datastores use GCM mode for authenticated encryption
- **PBKDF2 Key Derivation**: Secure key derivation with 100,000 iterations and unique salt per datastore
- **Cryptographic Parameters**: Each datastore specifies its cipher mode, salt, and iterations
- **Authenticated Encryption**: GCM mode provides authentication tags for tamper detection

