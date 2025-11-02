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
    from Crypto.Util.Padding import pad
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad

from pwmanager.crypto import (
    AES_BLOCK_SIZE, LEGACY_CIPHER, LEGACY_CIPHER_MODE, DEFAULT_CIPHER, DEFAULT_CIPHER_MODE,
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
def legacy_datastore(test_salt):
    """Create a legacy datastore (without cipher/cipher_mode)"""
    passphrase = "test"
    key = derive_key(passphrase, test_salt)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    challenge = derive_challenge(passphrase, test_salt)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_challenge = cipher.encrypt(pad(challenge, AES.block_size))
    
    return {
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'store': {}
    }


@pytest.fixture
def cbc_datastore(test_passphrase, test_salt):
    """Create a CBC mode datastore with PBKDF2 key derivation"""
    key = derive_key(test_passphrase, test_salt)
    challenge = derive_challenge(test_passphrase, test_salt)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_challenge = cipher.encrypt(pad(challenge, AES.block_size))
    
    return {
        'cipher': LEGACY_CIPHER,
        'cipher_mode': LEGACY_CIPHER_MODE,
        'key_derivation': 'PBKDF2',
        'salt': b64encode(test_salt).decode('utf-8'),
        'iterations': 100000,
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'store': {}
    }


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


@pytest.fixture
def cbc_datastore_with_entries(test_passphrase, test_salt):
    """Create a CBC datastore with PBKDF2 key derivation and password entries"""
    key = derive_key(test_passphrase, test_salt)
    challenge = derive_challenge(test_passphrase, test_salt)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_challenge = cipher.encrypt(pad(challenge, AES.block_size))
    
    datastore = {
        'cipher': LEGACY_CIPHER,
        'cipher_mode': LEGACY_CIPHER_MODE,
        'key_derivation': 'PBKDF2',
        'salt': b64encode(test_salt).decode('utf-8'),
        'iterations': 100000,
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'store': {}
    }
    
    # Add some password entries
    entries_data = {
        'site1.com': {'username': 'user1', 'password': 'pass1'},
        'site2.com': {'username': 'user2', 'password': 'pass2'},
    }
    
    for site_name, entry_data in entries_data.items():
        entry_iv = get_random_bytes(AES_BLOCK_SIZE)
        entry_cipher = AES.new(key, AES.MODE_CBC, iv=entry_iv)
        entry_json = dumps(entry_data).encode('utf-8')
        encrypted = entry_cipher.encrypt(pad(entry_json, AES.block_size))
        
        datastore['store'][site_name] = {
            'iv': b64encode(entry_iv).decode('utf-8'),
            'data': b64encode(encrypted).decode('utf-8')
        }
    
    return datastore

