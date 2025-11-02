"""
Tests for datastore operations module.
"""

import os
import pytest
from base64 import b64encode, b64decode
from json import loads, dumps

# Import cryptographic libraries
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes

from pwmanager.datastore import (
    validate_store_path, create_backup_file,
    load_datastore, save_datastore, verify_passphrase, initialize_datastore,
    decrypt_entry, encrypt_entry
)
from pwmanager.crypto import (
    AES_BLOCK_SIZE, get_random_bytes,
    DEFAULT_CIPHER, DEFAULT_CIPHER_MODE, PBKDF2_SALT_SIZE,
    derive_key
)


class TestValidateStorePath:
    """Test validate_store_path function"""
    
    def test_valid_paths(self):
        """Test valid store paths"""
        assert validate_store_path('./data/store.pws') is True
        assert validate_store_path('store.pws') is True
        assert validate_store_path('test/store.pws') is True
    
    def test_invalid_paths(self):
        """Test invalid store paths"""
        assert validate_store_path('') is False
        assert validate_store_path('../store.pws') is False
        assert validate_store_path('/etc/passwd') is False
        assert validate_store_path('/proc/store.pws') is False
        assert validate_store_path('/sys/store.pws') is False
        assert validate_store_path('/dev/store.pws') is False
        assert validate_store_path('/absolute/path.pws') is False
    
    def test_dangerous_patterns(self):
        """Test detection of dangerous patterns"""
        assert validate_store_path('test/../store.pws') is False
        assert validate_store_path('/etc/store.pws') is False
        assert validate_store_path('/proc/store.pws') is False


class TestDatastoreFileOperations:
    """Test datastore file operations"""
    
    def test_save_and_load_datastore(self, temp_datastore_path, gcm_datastore):
        """Test saving and loading a datastore"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(gcm_datastore, temp_datastore_path)
        
        assert os.path.exists(temp_datastore_path)
        loaded = load_datastore(temp_datastore_path)
        assert loaded == gcm_datastore
    
    def test_create_backup_file(self, temp_datastore_path, gcm_datastore):
        """Test backup file creation"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(gcm_datastore, temp_datastore_path)
        
        backup_path = create_backup_file(temp_datastore_path)
        
        # Verify backup file exists
        assert os.path.exists(backup_path)
        
        # Verify backup file is in the same directory
        assert os.path.dirname(backup_path) == os.path.dirname(temp_datastore_path)
        
        # Verify backup filename contains timestamp pattern
        backup_filename = os.path.basename(backup_path)
        assert '_backup_' in backup_filename
        assert backup_filename.endswith('.pws')
        
        # Verify backup content matches original
        with open(backup_path, 'r') as f:
            backup_data = loads(f.read())
        assert backup_data == gcm_datastore


class TestVerifyPassphrase:
    """Test passphrase verification"""
    
    
    def test_verify_correct_passphrase_gcm(self, temp_datastore_path, gcm_datastore, test_passphrase):
        """Test verification with correct passphrase in GCM mode"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(gcm_datastore, temp_datastore_path)
        
        assert verify_passphrase(gcm_datastore, test_passphrase) is True
    
    def test_verify_wrong_passphrase(self, temp_datastore_path, gcm_datastore):
        """Test verification with wrong passphrase"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(gcm_datastore, temp_datastore_path)
        
        wrong_passphrase = "wrong_passphrase"
        assert verify_passphrase(gcm_datastore, wrong_passphrase) is False


class TestInitializeDatastore:
    """Test datastore initialization"""
    
    def test_initialize_datastore(self, temp_datastore_path, test_passphrase):
        """Test initializing a new datastore"""
        initialize_datastore(temp_datastore_path, test_passphrase)
        
        assert os.path.exists(temp_datastore_path)
        datastore = load_datastore(temp_datastore_path)
        
        assert 'cipher' in datastore
        assert 'cipher_mode' in datastore
        assert 'iv' in datastore
        assert 'challenge' in datastore
        assert 'store' in datastore
        assert datastore['cipher'] == 'AES'
        assert datastore['cipher_mode'] == 'GCM'  # Default is GCM
        assert 'tag' in datastore  # GCM requires tag


class TestEntryEncryptionDecryption:
    """Test password entry encryption and decryption"""
    
    def test_encrypt_decrypt_entry_gcm(self, test_key, gcm_datastore):
        """Test encrypting and decrypting a password entry in GCM mode"""
        username = 'testuser'
        password = 'testpass'
        
        entry = encrypt_entry(username, password, test_key, gcm_datastore['cipher_mode'])
        
        assert 'iv' in entry
        assert 'data' in entry
        assert 'tag' in entry  # GCM requires tag
        
        decrypted = decrypt_entry(entry, test_key, gcm_datastore['cipher_mode'])
        assert decrypted['username'] == username
        assert decrypted['password'] == password
    
    def test_gcm_missing_tag(self, test_key, gcm_datastore):
        """Test that GCM mode raises error when tag is missing"""
        entry = {
            'iv': b64encode(get_random_bytes(AES_BLOCK_SIZE)).decode('utf-8'),
            'data': 'test'
        }
        
        with pytest.raises(ValueError, match='GCM mode requires authentication tag'):
            decrypt_entry(entry, test_key, gcm_datastore['cipher_mode'])
