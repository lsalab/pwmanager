# Testing Guide for pwmanager

This document describes how to run the test suite for the password manager.

The password manager supports two secure cryptographic modes:
- **GCM (Galois/Counter Mode)**: Default for new datastores, provides authenticated encryption
- **CBC (Cipher Block Chaining)**: Legacy mode, supported for backward compatibility with existing datastores

Insecure or unnecessary modes (ECB, CFB, OFB, CTR) have been removed to maintain security best practices.

The test suite comprehensively covers all cryptographic operations, legacy migration, and edge cases.

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
pytest tests/test_pwmanager.py
```

Or from the root directory:

```bash
python3 -m pytest tests/test_pwmanager.py
```

Run specific test class:

```bash
pytest tests/test_pwmanager.py::TestValidateStorePath
```

Run specific test:

```bash
pytest tests/test_pwmanager.py::TestValidateStorePath::test_valid_paths
```

## Test Coverage

The test suite covers:

1. **Helper Functions**
   - `validate_store_path()` - Path validation tests
   - `get_aes_mode()` - Cipher mode conversion tests
   - `migrate_legacy_datastore()` - Legacy datastore migration tests

2. **Cryptographic Operations**
   - CBC mode encryption/decryption
   - GCM mode encryption/decryption
   - Authentication tag handling for GCM

3. **Challenge Operations**
   - Challenge generation
   - Challenge verification (CBC and GCM)
   - Wrong passphrase detection

4. **Datastore Operations**
   - Creating new datastores
   - Saving and loading datastores
   - Legacy datastore migration

5. **Password Entry Operations**
   - Adding entries (CBC and GCM)
   - Encrypting/decrypting entries
   - Multiple entries handling

6. **Edge Cases**
   - Empty passphrase
   - Unicode passphrase
   - Large entry data
   - Special characters in entries

## Test Structure

Tests are organized into classes by functionality:

- `TestValidateStorePath` - Path validation
- `TestGetAESMode` - Cipher mode conversion
- `TestMigrateLegacyDatastore` - Legacy migration
- `TestCBCEncryptionDecryption` - CBC mode operations
- `TestGCMEncryptionDecryption` - GCM mode operations
- `TestChallengeGeneration` - Challenge operations
- `TestDatastoreOperations` - File operations
- `TestPasswordEntryOperations` - Entry management
- `TestConstants` - Constant validation
- `TestEdgeCases` - Edge cases and error handling

## Running with Coverage

To check test coverage (requires pytest-cov):

```bash
pip install pytest-cov
pytest --cov=pwmanager --cov-report=html
```

This will generate an HTML coverage report in the `htmlcov/` directory.

