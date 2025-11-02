"""
Tests for datastore operations module.
"""

import os
import pytest
from base64 import b64encode, b64decode
from json import loads, dumps

# Import cryptographic libraries
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

from pwmanager.datastore import (
    validate_store_path, migrate_legacy_datastore, create_backup_file,
    load_datastore, save_datastore, verify_passphrase, initialize_datastore,
    decrypt_entry, encrypt_entry, migrate_datastore_to_gcm
)
from pwmanager.crypto import (
    AES_BLOCK_SIZE, get_random_bytes, LEGACY_CIPHER, LEGACY_CIPHER_MODE,
    LEGACY_KEY_DERIVATION, DEFAULT_CIPHER, DEFAULT_CIPHER_MODE
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


class TestMigrateLegacyDatastore:
    """Test migrate_legacy_datastore function"""
    
    def test_legacy_datastore_migration(self, legacy_datastore):
        """Test migration of legacy datastore"""
        was_migrated = migrate_legacy_datastore(legacy_datastore)
        assert was_migrated is True
        assert 'cipher' in legacy_datastore
        assert 'cipher_mode' in legacy_datastore
        assert 'key_derivation' in legacy_datastore
        assert legacy_datastore['cipher'] == LEGACY_CIPHER
        assert legacy_datastore['cipher_mode'] == LEGACY_CIPHER_MODE
        assert legacy_datastore['key_derivation'] == LEGACY_KEY_DERIVATION
    
    def test_already_migrated_datastore(self, cbc_datastore):
        """Test that already migrated datastore is not migrated again"""
        original_cipher = cbc_datastore['cipher']
        original_mode = cbc_datastore['cipher_mode']
        was_migrated = migrate_legacy_datastore(cbc_datastore)
        assert was_migrated is False
        assert cbc_datastore['cipher'] == original_cipher
        assert cbc_datastore['cipher_mode'] == original_mode
    
    def test_partial_legacy_datastore(self):
        """Test datastore with only one missing field"""
        ds1 = {'cipher': 'AES', 'iv': 'test', 'challenge': 'test'}
        was_migrated1 = migrate_legacy_datastore(ds1)
        assert was_migrated1 is True
        
        ds2 = {'cipher_mode': 'CBC', 'iv': 'test', 'challenge': 'test'}
        was_migrated2 = migrate_legacy_datastore(ds2)
        assert was_migrated2 is True


class TestDatastoreFileOperations:
    """Test datastore file operations"""
    
    def test_save_and_load_datastore(self, temp_datastore_path, cbc_datastore):
        """Test saving and loading a datastore"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(cbc_datastore, temp_datastore_path)
        
        assert os.path.exists(temp_datastore_path)
        loaded = load_datastore(temp_datastore_path)
        assert loaded == cbc_datastore
    
    def test_create_backup_file(self, temp_datastore_path, cbc_datastore):
        """Test backup file creation"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(cbc_datastore, temp_datastore_path)
        
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
        assert backup_data == cbc_datastore


class TestVerifyPassphrase:
    """Test passphrase verification"""
    
    def test_verify_correct_passphrase_cbc(self, temp_datastore_path, cbc_datastore, test_passphrase):
        """Test verification with correct passphrase in CBC mode"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(cbc_datastore, temp_datastore_path)
        
        assert verify_passphrase(cbc_datastore, test_passphrase) is True
    
    def test_verify_correct_passphrase_gcm(self, temp_datastore_path, gcm_datastore, test_passphrase):
        """Test verification with correct passphrase in GCM mode"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(gcm_datastore, temp_datastore_path)
        
        assert verify_passphrase(gcm_datastore, test_passphrase) is True
    
    def test_verify_wrong_passphrase(self, temp_datastore_path, cbc_datastore):
        """Test verification with wrong passphrase"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(cbc_datastore, temp_datastore_path)
        
        wrong_passphrase = "wrong_passphrase"
        assert verify_passphrase(cbc_datastore, wrong_passphrase) is False


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
    
    def test_encrypt_decrypt_entry_cbc(self, test_key, cbc_datastore):
        """Test encrypting and decrypting a password entry in CBC mode"""
        username = 'testuser'
        password = 'testpass'
        
        entry = encrypt_entry(username, password, test_key, cbc_datastore['cipher_mode'])
        
        assert 'iv' in entry
        assert 'data' in entry
        assert 'tag' not in entry  # CBC doesn't have tag
        
        decrypted = decrypt_entry(entry, test_key, cbc_datastore['cipher_mode'])
        assert decrypted['username'] == username
        assert decrypted['password'] == password
    
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


class TestMigration:
    """Test datastore migration from CBC to GCM"""
    
    @pytest.fixture
    def cbc_datastore_with_entries(self, test_key, test_challenge):
        """Create a CBC datastore with password entries"""
        iv = get_random_bytes(AES_BLOCK_SIZE)
        cipher = AES.new(test_key, AES.MODE_CBC, iv=iv)
        encrypted_challenge = cipher.encrypt(pad(test_challenge, AES.block_size))
        
        datastore = {
            'cipher': 'AES',
            'cipher_mode': 'CBC',
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
            entry_cipher = AES.new(test_key, AES.MODE_CBC, iv=entry_iv)
            entry_json = dumps(entry_data).encode('utf-8')
            encrypted = entry_cipher.encrypt(pad(entry_json, AES.block_size))
            
            datastore['store'][site_name] = {
                'iv': b64encode(entry_iv).decode('utf-8'),
                'data': b64encode(encrypted).decode('utf-8')
            }
        
        return datastore
    
    def test_migrate_cbc_to_gcm_success(self, temp_datastore_path, cbc_datastore_with_entries, 
                                        test_key, test_passphrase):
        """Test successful migration from CBC to GCM"""
        # Save CBC datastore
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(cbc_datastore_with_entries, temp_datastore_path)
        
        # Perform migration
        success = migrate_datastore_to_gcm(temp_datastore_path, test_key, test_passphrase)
        assert success is True
        
        # Verify backup was created
        backup_files = [f for f in os.listdir(os.path.dirname(temp_datastore_path)) 
                       if f.endswith('.pws') and '_backup_' in f]
        assert len(backup_files) >= 1
        
        # Load migrated datastore
        migrated = load_datastore(temp_datastore_path)
        
        # Verify migration to GCM
        assert migrated['cipher'] == 'AES'
        assert migrated['cipher_mode'] == 'GCM'
        assert 'tag' in migrated  # GCM requires tag
        
        # Verify entries were migrated
        assert len(migrated['store']) == len(cbc_datastore_with_entries['store'])
        
        # Verify entries can be decrypted with GCM
        for site_name, entry in migrated['store'].items():
            assert 'tag' in entry  # GCM entries have tags
            decrypted = decrypt_entry(entry, test_key, 'GCM')
            assert 'username' in decrypted
            assert 'password' in decrypted
    
    def test_migrate_already_gcm(self, temp_datastore_path, gcm_datastore, test_key, test_passphrase):
        """Test migration when datastore is already in GCM mode"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(gcm_datastore, temp_datastore_path)
        
        # Attempt migration
        success = migrate_datastore_to_gcm(temp_datastore_path, test_key, test_passphrase)
        assert success is False
        
        # Verify datastore unchanged
        loaded = load_datastore(temp_datastore_path)
        assert loaded['cipher_mode'] == 'GCM'
    
    def test_migrate_wrong_passphrase(self, temp_datastore_path, cbc_datastore_with_entries):
        """Test migration with wrong passphrase fails"""
        os.makedirs(os.path.dirname(temp_datastore_path), exist_ok=True)
        save_datastore(cbc_datastore_with_entries, temp_datastore_path)
        
        wrong_passphrase = "wrong_passphrase"
        wrong_key = SHA256.new(data=wrong_passphrase.encode('utf-8')).digest()
        
        # Migration should fail with wrong passphrase
        with pytest.raises((ValueError, Exception)):
            migrate_datastore_to_gcm(temp_datastore_path, wrong_key, wrong_passphrase)
        
        # Verify datastore was restored from backup
        loaded = load_datastore(temp_datastore_path)
        assert loaded['cipher_mode'] == 'CBC'

