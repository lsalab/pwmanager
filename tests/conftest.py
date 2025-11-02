"""
Shared pytest fixtures for password manager tests.
"""

import os
import tempfile
import shutil
import pytest
from base64 import b64encode
from json import dumps

# Import cryptographic libraries
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes

from pwmanager.crypto import (
    AES_BLOCK_SIZE, DEFAULT_CIPHER, DEFAULT_CIPHER_MODE,
    PBKDF2_SALT_SIZE, get_random_bytes as crypto_get_random_bytes,
    derive_key, derive_challenge
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_datastore_path(temp_dir):
    """Return a temporary datastore file path"""
    return os.path.join(temp_dir, 'test_store.pws')


@pytest.fixture
def test_passphrase():
    """Return a test passphrase"""
    return "test_passphrase_123"


@pytest.fixture
def test_key(test_passphrase):
    """Generate a test encryption key from passphrase using PBKDF2"""
    salt = crypto_get_random_bytes(PBKDF2_SALT_SIZE)
    return derive_key(test_passphrase, salt)


@pytest.fixture
def test_challenge(test_passphrase):
    """Generate a test challenge from passphrase using PBKDF2"""
    salt = crypto_get_random_bytes(PBKDF2_SALT_SIZE)
    return derive_challenge(test_passphrase, salt)


@pytest.fixture
def test_salt():
    """Return a test salt for PBKDF2"""
    return crypto_get_random_bytes(PBKDF2_SALT_SIZE)


@pytest.fixture
def gcm_datastore(test_passphrase, test_salt):
    """Create a GCM mode datastore with PBKDF2 key derivation"""
    key = derive_key(test_passphrase, test_salt)
    challenge = derive_challenge(test_passphrase, test_salt)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    encrypted_challenge, tag = cipher.encrypt_and_digest(challenge)
    
    return {
        'cipher': DEFAULT_CIPHER,
        'cipher_mode': DEFAULT_CIPHER_MODE,
        'key_derivation': 'PBKDF2',
        'salt': b64encode(test_salt).decode('utf-8'),
        'iterations': 100000,
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'store': {}
    }


