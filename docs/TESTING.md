# Testing Guide for pwmanager

This document describes how to run the test suite for the password manager.

The password manager uses PBKDF2 for key derivation and supports two secure cryptographic modes:
- **GCM (Galois/Counter Mode)**: Default for new datastores, provides authenticated encryption
- **CBC (Cipher Block Chaining)**: Legacy mode, supported for backward compatibility with existing datastores

Insecure or unnecessary modes (ECB, CFB, OFB, CTR) have been removed to maintain security best practices.

The test suite comprehensively covers all cryptographic operations, datastore operations, and edge cases.

## Prerequisites

Install the test dependencies:

```bash
pip install -r requirements-test.txt
```

Or install pytest directly:

```bash
pip install pytest pycryptodome
```

## Running Tests

Run all tests:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

Run specific test file:

```bash
pytest tests/test_crypto.py
pytest tests/test_datastore.py
pytest tests/test_pwmanager.py
```

Or from the root directory:

```bash
python3 -m pytest tests/test_crypto.py
```

Run specific test class:

```bash
pytest tests/test_crypto.py::TestGetAESMode
pytest tests/test_datastore.py::TestValidateStorePath
```

Run specific test:

```bash
pytest tests/test_crypto.py::TestGetAESMode::test_valid_modes
pytest tests/test_datastore.py::TestValidateStorePath::test_valid_paths
```

## Test Coverage

The test suite covers:

1. **Cryptographic Operations** (`test_crypto.py`)
   - `get_aes_mode()` - Cipher mode conversion
   - `derive_key()` - Key derivation from passphrase
   - `derive_challenge()` - Challenge generation
   - `generate_random_password()` - Random password generation
   - CBC and GCM mode encryption/decryption
   - Authentication tag handling for GCM
   - Constants validation

2. **Datastore Operations** (`test_datastore.py`)
   - `validate_store_path()` - Path validation
   - `migrate_legacy_datastore()` - Legacy cipher mode migration
   - `load_datastore()` / `save_datastore()` - File operations
   - `create_backup_file()` - Backup creation
   - `verify_passphrase()` - Passphrase verification
   - `initialize_datastore()` - New datastore creation
   - `encrypt_entry()` / `decrypt_entry()` - Entry encryption/decryption
   - `migrate_datastore_to_gcm()` - CBC to GCM migration

3. **Integration Tests** (`test_pwmanager.py`)
   - Path validation (integration)
   - Application-level functionality

## Prerequisites

- Python >= 3.8
- pytest >= 7.0.0
- pycryptodome >= 3.15.0

## Test Structure

Tests are organized by module, matching the codebase structure:

### `tests/test_crypto.py` - Cryptographic Operations
- `TestGetAESMode` - Cipher mode conversion
- `TestKeyDerivation` - Key and challenge derivation
- `TestRandomPassword` - Random password generation
- `TestCBCEncryptionDecryption` - CBC mode operations
- `TestGCMEncryptionDecryption` - GCM mode operations
- `TestConstants` - Cryptographic constants

### `tests/test_datastore.py` - Datastore Operations
- `TestValidateStorePath` - Path validation
- `TestMigrateLegacyDatastore` - Legacy cipher mode migration
- `TestDatastoreFileOperations` - File save/load/backup
- `TestVerifyPassphrase` - Passphrase verification
- `TestInitializeDatastore` - Datastore initialization
- `TestEntryEncryptionDecryption` - Entry encryption/decryption
- `TestMigration` - CBC to GCM migration

### `tests/test_pwmanager.py` - Integration Tests
- `TestValidateStorePath` - Path validation (integration)

Shared fixtures are available in `tests/conftest.py`.

## Running with Coverage

To check test coverage (requires pytest-cov):

```bash
pip install pytest-cov
pytest --cov=pwmanager --cov-report=html
```

This will generate an HTML coverage report in the `htmlcov/` directory.

