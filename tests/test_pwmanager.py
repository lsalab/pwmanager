#!/usr/bin/env python3
"""
Comprehensive pytest test suite for pwmanager.py
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
import pytest
from json import loads, dumps
from base64 import b64encode, b64decode

# Add parent directory to path to import pwmanager
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the module to test
import pwmanager

# Import cryptographic functions
try:
    from Crypto.Hash import SHA256
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    from Cryptodome.Hash import SHA256
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util.Padding import pad, unpad


# Test fixtures
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
    iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
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
    iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
    cipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
    encrypted_challenge = cipher.encrypt(pad(test_challenge, AES.block_size))
    
    return {
        'cipher': 'AES',
        'cipher_mode': 'CBC',
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'store': {}
    }


@pytest.fixture
def gcm_datastore(test_key, test_challenge):
    """Create a GCM mode datastore"""
    iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
    cipher = AES.new(test_key, AES.MODE_GCM, nonce=iv)
    encrypted_challenge, tag = cipher.encrypt_and_digest(test_challenge)  # GCM doesn't need padding
    
    return {
        'cipher': 'AES',
        'cipher_mode': 'GCM',
        'iv': b64encode(iv).decode('utf-8'),
        'challenge': b64encode(encrypted_challenge).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'store': {}
    }


# Test helper functions
class TestValidateStorePath:
    """Test validate_store_path function"""
    
    def test_valid_paths(self):
        """Test valid store paths"""
        assert pwmanager.validate_store_path('./data/store.pws') is True
        assert pwmanager.validate_store_path('store.pws') is True
        assert pwmanager.validate_store_path('test/store.pws') is True
    
    def test_invalid_paths(self):
        """Test invalid store paths"""
        assert pwmanager.validate_store_path('') is False
        assert pwmanager.validate_store_path('../store.pws') is False
        assert pwmanager.validate_store_path('/etc/passwd') is False
        assert pwmanager.validate_store_path('/proc/store.pws') is False
        assert pwmanager.validate_store_path('/sys/store.pws') is False
        assert pwmanager.validate_store_path('/dev/store.pws') is False
        assert pwmanager.validate_store_path('/absolute/path.pws') is False
    
    def test_dangerous_patterns(self):
        """Test detection of dangerous patterns"""
        assert pwmanager.validate_store_path('test/../store.pws') is False
        # Note: 'etc/store.pws' is allowed as it's not '/etc' - only absolute paths starting with /etc are blocked
        assert pwmanager.validate_store_path('/etc/store.pws') is False
        assert pwmanager.validate_store_path('/proc/store.pws') is False


class TestGetAESMode:
    """Test get_aes_mode function"""
    
    def test_valid_modes(self):
        """Test valid cipher modes"""
        assert pwmanager.get_aes_mode('GCM') == AES.MODE_GCM
        assert pwmanager.get_aes_mode('CBC') == AES.MODE_CBC
    
    def test_case_insensitive(self):
        """Test case insensitivity"""
        assert pwmanager.get_aes_mode('gcm') == AES.MODE_GCM
        assert pwmanager.get_aes_mode('Cbc') == AES.MODE_CBC
        assert pwmanager.get_aes_mode('GCM') == AES.MODE_GCM
        assert pwmanager.get_aes_mode('cbc') == AES.MODE_CBC
    
    def test_invalid_mode(self):
        """Test invalid cipher mode raises ValueError"""
        with pytest.raises(ValueError, match='Unsupported cipher mode'):
            pwmanager.get_aes_mode('INVALID')
    
    def test_removed_insecure_modes(self):
        """Test that insecure/unnecessary modes are rejected"""
        insecure_modes = ['ECB', 'CFB', 'OFB', 'CTR']
        for mode in insecure_modes:
            with pytest.raises(ValueError, match='Only GCM and CBC are supported'):
                pwmanager.get_aes_mode(mode)


class TestMigrateLegacyDatastore:
    """Test migrate_legacy_datastore function"""
    
    def test_legacy_datastore_migration(self, legacy_datastore):
        """Test migration of legacy datastore"""
        was_migrated = pwmanager.migrate_legacy_datastore(legacy_datastore)
        assert was_migrated is True
        assert 'cipher' in legacy_datastore
        assert 'cipher_mode' in legacy_datastore
        assert legacy_datastore['cipher'] == pwmanager.LEGACY_CIPHER
        assert legacy_datastore['cipher_mode'] == pwmanager.LEGACY_CIPHER_MODE
    
    def test_already_migrated_datastore(self, cbc_datastore):
        """Test that already migrated datastore is not migrated again"""
        original_cipher = cbc_datastore['cipher']
        original_mode = cbc_datastore['cipher_mode']
        was_migrated = pwmanager.migrate_legacy_datastore(cbc_datastore)
        assert was_migrated is False
        assert cbc_datastore['cipher'] == original_cipher
        assert cbc_datastore['cipher_mode'] == original_mode
    
    def test_partial_legacy_datastore(self):
        """Test datastore with only one missing field"""
        ds1 = {'cipher': 'AES', 'iv': 'test', 'challenge': 'test'}
        was_migrated1 = pwmanager.migrate_legacy_datastore(ds1)
        assert was_migrated1 is True
        
        ds2 = {'cipher_mode': 'CBC', 'iv': 'test', 'challenge': 'test'}
        was_migrated2 = pwmanager.migrate_legacy_datastore(ds2)
        assert was_migrated2 is True


# Test cryptographic operations
class TestCBCEncryptionDecryption:
    """Test CBC mode encryption and decryption"""
    
    def test_cbc_encrypt_decrypt(self, test_key):
        """Test CBC encryption and decryption"""
        plaintext = b"test data to encrypt"
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        cipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
        
        # Encrypt
        encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
        
        # Decrypt
        decipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
        decrypted = unpad(decipher.decrypt(encrypted), AES.block_size)
        
        assert decrypted == plaintext
    
    def test_cbc_entry_encrypt_decrypt(self, test_key, cbc_datastore):
        """Test encrypting and decrypting a password entry in CBC mode"""
        entry_data = {'username': 'testuser', 'password': 'testpass'}
        entry_json = dumps(entry_data).encode('utf-8')
        
        # Encrypt
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        aes_mode = pwmanager.get_aes_mode(cbc_datastore['cipher_mode'])
        cipher = AES.new(test_key, aes_mode, iv=iv)
        encrypted = cipher.encrypt(pad(entry_json, AES.block_size))
        
        entry = {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(encrypted).decode('utf-8')
        }
        
        # Decrypt
        decrypted_data = pwmanager.decryptEntry(entry, test_key, cbc_datastore['cipher_mode'])
        assert decrypted_data == entry_data


class TestGCMEncryptionDecryption:
    """Test GCM mode encryption and decryption"""
    
    def test_gcm_encrypt_decrypt(self, test_key):
        """Test GCM encryption and decryption"""
        plaintext = b"test data to encrypt"
        nonce = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        cipher = AES.new(test_key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Decrypt
        decipher = AES.new(test_key, AES.MODE_GCM, nonce=nonce)
        decrypted = decipher.decrypt_and_verify(ciphertext, tag)
        
        assert decrypted == plaintext
    
    def test_gcm_entry_encrypt_decrypt(self, test_key, gcm_datastore):
        """Test encrypting and decrypting a password entry in GCM mode"""
        entry_data = {'username': 'testuser', 'password': 'testpass'}
        entry_json = dumps(entry_data).encode('utf-8')
        
        # Encrypt
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        aes_mode = pwmanager.get_aes_mode(gcm_datastore['cipher_mode'])
        cipher = AES.new(test_key, aes_mode, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(entry_json)  # GCM doesn't need padding
        
        entry = {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }
        
        # Decrypt
        decrypted_data = pwmanager.decryptEntry(entry, test_key, gcm_datastore['cipher_mode'])
        assert decrypted_data == entry_data
    
    def test_gcm_missing_tag(self, test_key, gcm_datastore):
        """Test that GCM mode raises error when tag is missing"""
        entry = {
            'iv': b64encode(get_random_bytes(pwmanager.AES_BLOCK_SIZE)).decode('utf-8'),
            'data': 'test'
        }
        
        with pytest.raises(ValueError, match='GCM mode requires authentication tag'):
            pwmanager.decryptEntry(entry, test_key, gcm_datastore['cipher_mode'])
    
    def test_gcm_invalid_tag(self, test_key, gcm_datastore):
        """Test that GCM mode raises error with invalid tag"""
        entry_data = {'username': 'testuser', 'password': 'testpass'}
        entry_json = dumps(entry_data).encode('utf-8')
        
        # Encrypt
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        aes_mode = pwmanager.get_aes_mode(gcm_datastore['cipher_mode'])
        cipher = AES.new(test_key, aes_mode, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(entry_json)  # GCM doesn't need padding
        
        # Modify tag
        invalid_tag = bytearray(tag)
        invalid_tag[0] ^= 1
        
        entry = {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(bytes(invalid_tag)).decode('utf-8')
        }
        
        # Decrypt should fail
        with pytest.raises(ValueError):
            pwmanager.decryptEntry(entry, test_key, gcm_datastore['cipher_mode'])


# Test challenge operations
class TestChallengeGeneration:
    """Test challenge generation and verification"""
    
    def test_challenge_generation(self, test_passphrase, test_challenge):
        """Test that challenge is generated correctly"""
        challenge_string = ''
        for char in test_passphrase:
            challenge_string += chr(ord(char) ^ 0xff)
        expected = SHA256.new(data=challenge_string.encode('utf-8')).digest()
        assert expected == test_challenge
    
    def test_challenge_verification_cbc(self, test_key, test_challenge, cbc_datastore):
        """Test challenge verification in CBC mode"""
        iv = b64decode(cbc_datastore['iv'])
        challenge_encrypted = b64decode(cbc_datastore['challenge'])
        
        cipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
        challenge_decrypted = cipher.decrypt(challenge_encrypted)
        challenge_decrypted = unpad(challenge_decrypted, AES.block_size)
        
        assert challenge_decrypted == test_challenge
    
    def test_challenge_verification_gcm(self, test_key, test_challenge, gcm_datastore):
        """Test challenge verification in GCM mode"""
        nonce = b64decode(gcm_datastore['iv'])
        challenge_encrypted = b64decode(gcm_datastore['challenge'])
        tag = b64decode(gcm_datastore['tag'])
        
        cipher = AES.new(test_key, AES.MODE_GCM, nonce=nonce)
        challenge_decrypted = cipher.decrypt_and_verify(challenge_encrypted, tag)  # GCM doesn't need unpadding
        
        assert challenge_decrypted == test_challenge
    
    def test_challenge_wrong_passphrase(self, test_passphrase):
        """Test that wrong passphrase generates different challenge"""
        wrong_passphrase = "wrong_passphrase"
        
        challenge_string_correct = ''
        for char in test_passphrase:
            challenge_string_correct += chr(ord(char) ^ 0xff)
        challenge_correct = SHA256.new(data=challenge_string_correct.encode('utf-8')).digest()
        
        challenge_string_wrong = ''
        for char in wrong_passphrase:
            challenge_string_wrong += chr(ord(char) ^ 0xff)
        challenge_wrong = SHA256.new(data=challenge_string_wrong.encode('utf-8')).digest()
        
        assert challenge_correct != challenge_wrong


# Test datastore operations
class TestDatastoreOperations:
    """Test datastore creation and file operations"""
    
    def test_create_datastore_file(self, temp_datastore_path, test_passphrase, test_key, test_challenge):
        """Test creating a datastore file"""
        # Create datastore structure
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        cipher_mode = pwmanager.DEFAULT_CIPHER_MODE
        aes_mode = pwmanager.get_aes_mode(cipher_mode)
        
        if cipher_mode == 'GCM':
            cipher = AES.new(test_key, aes_mode, nonce=iv)
            encrypted_challenge, tag = cipher.encrypt_and_digest(test_challenge)  # GCM doesn't need padding
            datastore = {
                'cipher': pwmanager.DEFAULT_CIPHER,
                'cipher_mode': cipher_mode,
                'iv': b64encode(iv).decode('utf-8'),
                'challenge': b64encode(encrypted_challenge).decode('utf-8'),
                'tag': b64encode(tag).decode('utf-8'),
                'store': {}
            }
        else:
            cipher = AES.new(test_key, aes_mode, iv=iv)
            encrypted_challenge = cipher.encrypt(pad(test_challenge, AES.block_size))
            datastore = {
                'cipher': pwmanager.DEFAULT_CIPHER,
                'cipher_mode': cipher_mode,
                'iv': b64encode(iv).decode('utf-8'),
                'challenge': b64encode(encrypted_challenge).decode('utf-8'),
                'store': {}
            }
        
        # Write to file
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        with open(temp_datastore_path, 'w') as f:
            f.write(dumps(datastore, indent=2))
        
        # Verify file exists and is valid JSON
        assert os.path.exists(temp_datastore_path)
        with open(temp_datastore_path, 'r') as f:
            loaded = loads(f.read())
            assert loaded['cipher'] == pwmanager.DEFAULT_CIPHER
            assert loaded['cipher_mode'] == cipher_mode
    
    def test_save_datastore(self, temp_datastore_path, cbc_datastore):
        """Test saving a datastore"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        pwmanager.saveDatastore(cbc_datastore, temp_datastore_path)
        
        assert os.path.exists(temp_datastore_path)
        with open(temp_datastore_path, 'r') as f:
            loaded = loads(f.read())
            assert loaded == cbc_datastore
    
    def test_load_and_migrate_legacy(self, temp_datastore_path, legacy_datastore):
        """Test loading and migrating a legacy datastore"""
        # Write legacy datastore
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        with open(temp_datastore_path, 'w') as f:
            f.write(dumps(legacy_datastore, indent=2))
        
        # Load and migrate
        with open(temp_datastore_path, 'r') as f:
            loaded = loads(f.read())
        
        was_migrated = pwmanager.migrate_legacy_datastore(loaded)
        assert was_migrated is True
        
        # Save migrated datastore
        pwmanager.saveDatastore(loaded, temp_datastore_path)
        
        # Verify migration persisted
        with open(temp_datastore_path, 'r') as f:
            saved = loads(f.read())
            assert 'cipher' in saved
            assert 'cipher_mode' in saved


# Test password entry operations
class TestPasswordEntryOperations:
    """Test password entry encryption and decryption"""
    
    def test_add_entry_cbc(self, test_key, cbc_datastore):
        """Test adding a password entry in CBC mode"""
        site_name = "test.com"
        entry_data_dict = {'username': 'user1', 'password': 'pass1'}
        
        # Encrypt entry
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        aes_mode = pwmanager.get_aes_mode(cbc_datastore['cipher_mode'])
        cipher = AES.new(test_key, aes_mode, iv=iv)
        entry_json = dumps(entry_data_dict).encode('utf-8')
        encrypted = cipher.encrypt(pad(entry_json, AES.block_size))
        
        entry = {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(encrypted).decode('utf-8')
        }
        
        cbc_datastore['store'][site_name] = entry
        
        # Decrypt entry
        decrypted = pwmanager.decryptEntry(entry, test_key, cbc_datastore['cipher_mode'])
        assert decrypted == entry_data_dict
    
    def test_add_entry_gcm(self, test_key, gcm_datastore):
        """Test adding a password entry in GCM mode"""
        site_name = "test.com"
        entry_data_dict = {'username': 'user1', 'password': 'pass1'}
        
        # Encrypt entry
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        aes_mode = pwmanager.get_aes_mode(gcm_datastore['cipher_mode'])
        cipher = AES.new(test_key, aes_mode, nonce=iv)
        entry_json = dumps(entry_data_dict).encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(entry_json)  # GCM doesn't need padding
        
        entry = {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }
        
        gcm_datastore['store'][site_name] = entry
        
        # Decrypt entry
        decrypted = pwmanager.decryptEntry(entry, test_key, gcm_datastore['cipher_mode'])
        assert decrypted == entry_data_dict
    
    def test_multiple_entries(self, test_key, cbc_datastore):
        """Test storing and retrieving multiple password entries"""
        entries = {
            'site1.com': {'username': 'user1', 'password': 'pass1'},
            'site2.com': {'username': 'user2', 'password': 'pass2'},
            'site3.com': {'username': 'user3', 'password': 'pass3'}
        }
        
        # Encrypt and store entries
        for site_name, entry_data in entries.items():
            iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
            aes_mode = pwmanager.get_aes_mode(cbc_datastore['cipher_mode'])
            cipher = AES.new(test_key, aes_mode, iv=iv)
            entry_json = dumps(entry_data).encode('utf-8')
            encrypted = cipher.encrypt(pad(entry_json, AES.block_size))
            
            entry = {
                'iv': b64encode(iv).decode('utf-8'),
                'data': b64encode(encrypted).decode('utf-8')
            }
            
            cbc_datastore['store'][site_name] = entry
        
        # Decrypt and verify entries
        for site_name, expected_data in entries.items():
            entry = cbc_datastore['store'][site_name]
            decrypted = pwmanager.decryptEntry(entry, test_key, cbc_datastore['cipher_mode'])
            assert decrypted == expected_data


# Test constants and configuration
class TestConstants:
    """Test module constants"""
    
    def test_constants_defined(self):
        """Test that required constants are defined"""
        assert hasattr(pwmanager, 'AES_BLOCK_SIZE')
        assert hasattr(pwmanager, 'AES_KEY_SIZE')
        assert hasattr(pwmanager, 'PASSWORD_LENGTH')
        assert hasattr(pwmanager, 'LEGACY_CIPHER')
        assert hasattr(pwmanager, 'LEGACY_CIPHER_MODE')
        assert hasattr(pwmanager, 'DEFAULT_CIPHER')
        assert hasattr(pwmanager, 'DEFAULT_CIPHER_MODE')
    
    def test_constant_values(self):
        """Test constant values"""
        assert pwmanager.AES_BLOCK_SIZE == 16
        assert pwmanager.AES_KEY_SIZE == 32
        assert pwmanager.LEGACY_CIPHER == 'AES'
        assert pwmanager.LEGACY_CIPHER_MODE == 'CBC'
        assert pwmanager.DEFAULT_CIPHER == 'AES'
        assert pwmanager.DEFAULT_CIPHER_MODE == 'GCM'


# Test edge cases and error handling
class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_passphrase_challenge(self):
        """Test challenge generation with empty passphrase"""
        passphrase = ""
        challenge_string = ''
        for char in passphrase:
            challenge_string += chr(ord(char) ^ 0xff)
        challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
        assert len(challenge) == 32
    
    def test_unicode_passphrase(self):
        """Test challenge generation with unicode passphrase"""
        passphrase = "test_密码_🔒"
        key = SHA256.new(data=passphrase.encode('utf-8')).digest()
        assert len(key) == 32
        
        challenge_string = ''
        for char in passphrase:
            challenge_string += chr(ord(char) ^ 0xff)
        challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
        assert len(challenge) == 32
    
    def test_large_entry_data(self, test_key, cbc_datastore):
        """Test encryption with large entry data"""
        large_data = {'username': 'user', 'password': 'x' * 10000}
        entry_json = dumps(large_data).encode('utf-8')
        
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        aes_mode = pwmanager.get_aes_mode(cbc_datastore['cipher_mode'])
        cipher = AES.new(test_key, aes_mode, iv=iv)
        encrypted = cipher.encrypt(pad(entry_json, AES.block_size))
        
        entry = {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(encrypted).decode('utf-8')
        }
        
        decrypted = pwmanager.decryptEntry(entry, test_key, cbc_datastore['cipher_mode'])
        assert decrypted == large_data
    
    def test_special_characters_in_entry(self, test_key, cbc_datastore):
        """Test entry with special characters"""
        entry_data = {
            'username': 'user@example.com',
            'password': 'p@ssw0rd!#$%^&*()'
        }
        entry_json = dumps(entry_data).encode('utf-8')
        
        iv = get_random_bytes(pwmanager.AES_BLOCK_SIZE)
        aes_mode = pwmanager.get_aes_mode(cbc_datastore['cipher_mode'])
        cipher = AES.new(test_key, aes_mode, iv=iv)
        encrypted = cipher.encrypt(pad(entry_json, AES.block_size))
        
        entry = {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(encrypted).decode('utf-8')
        }
        
        decrypted = pwmanager.decryptEntry(entry, test_key, cbc_datastore['cipher_mode'])
        assert decrypted == entry_data

