"""
Tests for cryptographic operations module.
"""

import pytest
from base64 import b64encode
from json import dumps

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

from pwmanager.crypto import (
    get_aes_mode, derive_key, derive_challenge, generate_random_password,
    encrypt_data, decrypt_data,
    AES_BLOCK_SIZE, AES_KEY_SIZE, PASSWORD_LENGTH,
    LEGACY_CIPHER, LEGACY_CIPHER_MODE, DEFAULT_CIPHER, DEFAULT_CIPHER_MODE
)


class TestGetAESMode:
    """Test get_aes_mode function"""
    
    def test_valid_modes(self):
        """Test valid cipher modes"""
        assert get_aes_mode('GCM') == AES.MODE_GCM
        assert get_aes_mode('CBC') == AES.MODE_CBC
    
    def test_case_insensitive(self):
        """Test case insensitivity"""
        assert get_aes_mode('gcm') == AES.MODE_GCM
        assert get_aes_mode('Cbc') == AES.MODE_CBC
        assert get_aes_mode('GCM') == AES.MODE_GCM
        assert get_aes_mode('cbc') == AES.MODE_CBC
    
    def test_invalid_mode(self):
        """Test invalid cipher mode raises ValueError"""
        with pytest.raises(ValueError, match='Unsupported cipher mode'):
            get_aes_mode('INVALID')
    
    def test_removed_insecure_modes(self):
        """Test that insecure/unnecessary modes are rejected"""
        insecure_modes = ['ECB', 'CFB', 'OFB', 'CTR']
        for mode in insecure_modes:
            with pytest.raises(ValueError, match='Only GCM and CBC are supported'):
                get_aes_mode(mode)


class TestKeyDerivation:
    """Test key derivation functions"""
    
    def test_derive_key_sha256(self, test_passphrase, test_key):
        """Test SHA256 key derivation from passphrase (legacy)"""
        from pwmanager.crypto import derive_key_sha256
        derived_key = derive_key_sha256(test_passphrase)
        assert derived_key == test_key
        assert len(derived_key) == AES_KEY_SIZE
    
    def test_derive_challenge_sha256(self, test_passphrase, test_challenge):
        """Test SHA256 challenge derivation from passphrase (legacy)"""
        from pwmanager.crypto import derive_challenge_sha256
        derived_challenge = derive_challenge_sha256(test_passphrase)
        assert derived_challenge == test_challenge
        assert len(derived_challenge) == 32
    
    def test_derive_key_pbkdf2(self, test_passphrase):
        """Test PBKDF2 key derivation from passphrase"""
        from pwmanager.crypto import derive_key_pbkdf2, get_random_bytes, PBKDF2_SALT_SIZE
        salt = get_random_bytes(PBKDF2_SALT_SIZE)
        derived_key = derive_key_pbkdf2(test_passphrase, salt)
        assert len(derived_key) == AES_KEY_SIZE
        # Same passphrase + salt should produce same key
        derived_key2 = derive_key_pbkdf2(test_passphrase, salt)
        assert derived_key == derived_key2
        # Different salt should produce different key
        salt2 = get_random_bytes(PBKDF2_SALT_SIZE)
        derived_key3 = derive_key_pbkdf2(test_passphrase, salt2)
        assert derived_key != derived_key3
    
    def test_derive_challenge_pbkdf2(self, test_passphrase):
        """Test PBKDF2 challenge derivation from passphrase"""
        from pwmanager.crypto import derive_challenge_pbkdf2, get_random_bytes, PBKDF2_SALT_SIZE
        salt = get_random_bytes(PBKDF2_SALT_SIZE)
        derived_challenge = derive_challenge_pbkdf2(test_passphrase, salt)
        assert len(derived_challenge) == 32
        # Same passphrase + salt should produce same challenge
        derived_challenge2 = derive_challenge_pbkdf2(test_passphrase, salt)
        assert derived_challenge == derived_challenge2
    
    def test_empty_passphrase_key_sha256(self):
        """Test SHA256 key derivation with empty passphrase"""
        from pwmanager.crypto import derive_key_sha256
        key = derive_key_sha256("")
        assert len(key) == AES_KEY_SIZE
    
    def test_empty_passphrase_challenge_sha256(self):
        """Test SHA256 challenge derivation with empty passphrase"""
        from pwmanager.crypto import derive_challenge_sha256
        challenge = derive_challenge_sha256("")
        assert len(challenge) == 32
    
    def test_unicode_passphrase(self, test_passphrase):
        """Test with unicode passphrase"""
        from pwmanager.crypto import derive_key_sha256, derive_challenge_sha256
        passphrase = "test_密码_🔒"
        key = derive_key_sha256(passphrase)
        assert len(key) == AES_KEY_SIZE
        
        challenge = derive_challenge_sha256(passphrase)
        assert len(challenge) == 32
    
    def test_derive_key_without_salt_fails(self, test_passphrase):
        """Test that derive_key fails without salt for PBKDF2"""
        from pwmanager.crypto import DEFAULT_KEY_DERIVATION
        # Should fail when using PBKDF2 without salt
        try:
            derive_key(test_passphrase, DEFAULT_KEY_DERIVATION)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass  # Expected
    
    def test_derive_challenge_without_salt_fails(self, test_passphrase):
        """Test that derive_challenge fails without salt for PBKDF2"""
        from pwmanager.crypto import DEFAULT_KEY_DERIVATION
        # Should fail when using PBKDF2 without salt
        try:
            derive_challenge(test_passphrase, DEFAULT_KEY_DERIVATION)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass  # Expected


class TestRandomPassword:
    """Test random password generation"""
    
    def test_generate_random_password(self):
        """Test random password generation"""
        password = generate_random_password()
        assert isinstance(password, str)
        assert len(password) > 0
    
    def test_password_length(self):
        """Test password has reasonable length"""
        password = generate_random_password()
        # Base64 encoded 24 bytes should be 32 characters
        assert len(password) == 32


class TestCBCEncryptionDecryption:
    """Test CBC mode encryption and decryption"""
    
    def test_cbc_encrypt_decrypt(self, test_key):
        """Test CBC encryption and decryption"""
        plaintext = b"test data to encrypt"
        encrypted = encrypt_data(plaintext, test_key, 'CBC')
        
        assert 'iv' in encrypted
        assert 'data' in encrypted
        assert 'tag' not in encrypted  # CBC doesn't have tag
        
        decrypted = decrypt_data(encrypted, test_key, 'CBC')
        assert decrypted == plaintext
    
    def test_cbc_large_data(self, test_key):
        """Test CBC encryption with large data"""
        plaintext = b"x" * 10000
        encrypted = encrypt_data(plaintext, test_key, 'CBC')
        decrypted = decrypt_data(encrypted, test_key, 'CBC')
        assert decrypted == plaintext


class TestGCMEncryptionDecryption:
    """Test GCM mode encryption and decryption"""
    
    def test_gcm_encrypt_decrypt(self, test_key):
        """Test GCM encryption and decryption"""
        plaintext = b"test data to encrypt"
        encrypted = encrypt_data(plaintext, test_key, 'GCM')
        
        assert 'iv' in encrypted
        assert 'data' in encrypted
        assert 'tag' in encrypted  # GCM requires tag
        
        decrypted = decrypt_data(encrypted, test_key, 'GCM')
        assert decrypted == plaintext
    
    def test_gcm_missing_tag(self, test_key):
        """Test that GCM mode raises error when tag is missing"""
        plaintext = b"test data"
        encrypted = encrypt_data(plaintext, test_key, 'GCM')
        # Remove tag to test error handling
        encrypted_without_tag = {
            'iv': encrypted['iv'],
            'data': encrypted['data']
        }
        
        with pytest.raises(ValueError, match='GCM mode requires authentication tag'):
            decrypt_data(encrypted_without_tag, test_key, 'GCM')
    
    def test_gcm_invalid_tag(self, test_key):
        """Test that GCM mode raises error with invalid tag"""
        plaintext = b"test data"
        encrypted = encrypt_data(plaintext, test_key, 'GCM')
        
        # Modify tag
        from base64 import b64decode, b64encode
        invalid_tag = bytearray(b64decode(encrypted['tag']))
        invalid_tag[0] ^= 1
        
        encrypted_invalid = {
            'iv': encrypted['iv'],
            'data': encrypted['data'],
            'tag': b64encode(bytes(invalid_tag)).decode('utf-8')
        }
        
        with pytest.raises(ValueError):
            decrypt_data(encrypted_invalid, test_key, 'GCM')
    
    def test_gcm_large_data(self, test_key):
        """Test GCM encryption with large data"""
        plaintext = b"x" * 10000
        encrypted = encrypt_data(plaintext, test_key, 'GCM')
        decrypted = decrypt_data(encrypted, test_key, 'GCM')
        assert decrypted == plaintext


class TestConstants:
    """Test module constants"""
    
    def test_constants_defined(self):
        """Test that required constants are defined"""
        assert AES_BLOCK_SIZE == 16
        assert AES_KEY_SIZE == 32
        assert PASSWORD_LENGTH == 24
        assert LEGACY_CIPHER == 'AES'
        assert LEGACY_CIPHER_MODE == 'CBC'
        assert DEFAULT_CIPHER == 'AES'
        assert DEFAULT_CIPHER_MODE == 'GCM'
    
    def test_constant_values(self):
        """Test constant values are correct"""
        assert AES_BLOCK_SIZE == 16
        assert AES_KEY_SIZE == 32
        assert LEGACY_CIPHER == 'AES'
        assert LEGACY_CIPHER_MODE == 'CBC'
        assert DEFAULT_CIPHER == 'AES'
        assert DEFAULT_CIPHER_MODE == 'GCM'

