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
    from Crypto.Hash import SHA256
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad
except ImportError:
    from Cryptodome.Hash import SHA256
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad

from pwmanager.crypto import AES_BLOCK_SIZE, LEGACY_CIPHER, LEGACY_CIPHER_MODE, DEFAULT_CIPHER, DEFAULT_CIPHER_MODE


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
    """Generate a test encryption key from passphrase"""
    return SHA256.new(data=test_passphrase.encode('utf-8')).digest()


@pytest.fixture
def test_challenge(test_passphrase):
    """Generate a test challenge from passphrase"""
    challenge_string = ''
    for char in test_passphrase:
        challenge_string += chr(ord(char) ^ 0xff)
    return SHA256.new(data=challenge_string.encode('utf-8')).digest()


@pytest.fixture
def legacy_datastore():
    """Create a legacy datastore (without cipher/cipher_mode)"""
    key = SHA256.new(data="test".encode('utf-8')).digest()
    iv = get_random_bytes(AES_BLOCK_SIZE)
    challenge_string = ''
    for char in "test":
        challenge_string += chr(ord(char) ^ 0xff)
    challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_challenge = cipher.encrypt(pad(challenge, AES.block_size))
    
    return {
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'store': {}
    }


@pytest.fixture
def cbc_datastore(test_key, test_challenge):
    """Create a CBC mode datastore"""
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
    encrypted_challenge = cipher.encrypt(pad(test_challenge, AES.block_size))
    
    return {
        'cipher': LEGACY_CIPHER,
        'cipher_mode': LEGACY_CIPHER_MODE,
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'store': {}
    }


@pytest.fixture
def gcm_datastore(test_key, test_challenge):
    """Create a GCM mode datastore"""
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(test_key, AES.MODE_GCM, nonce=iv)
    encrypted_challenge, tag = cipher.encrypt_and_digest(test_challenge)
    
    return {
        'cipher': DEFAULT_CIPHER,
        'cipher_mode': DEFAULT_CIPHER_MODE,
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'store': {}
    }

