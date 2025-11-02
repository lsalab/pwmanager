"""
Cryptographic operations for password manager.

Handles encryption, decryption, key derivation, and cryptographic utilities.
"""

import sys
# Try importing from Crypto (pycryptodome standard package)
# Fall back to Cryptodome (pycryptodomex or older installations)
try:
    from Crypto.Hash import SHA256
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except (ImportError, ModuleNotFoundError):
    try:
        from Cryptodome.Hash import SHA256
        from Cryptodome.Cipher import AES
        from Cryptodome.Random import get_random_bytes
        from Cryptodome.Util.Padding import pad, unpad
    except ImportError as e:
        sys.stderr.write(
            "ERROR: Could not import cryptographic libraries.\n"
            "Please install PyCryptodome or PyCryptodomex:\n"
            "  pip install pycryptodome\n"
            "  # or\n"
            "  pip install pycryptodomex\n\n"
        )
        sys.exit(1)

from base64 import b64encode, b64decode

# Constants
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32
PASSWORD_LENGTH = 24

# Cryptographic defaults
LEGACY_CIPHER = 'AES'
LEGACY_CIPHER_MODE = 'CBC'

# Default cryptographic parameters for new datastores (most secure)
DEFAULT_CIPHER = 'AES'
DEFAULT_CIPHER_MODE = 'GCM'


def get_aes_mode(cipher_mode: str):
    """
    Convert cipher mode string to AES mode constant.
    
    Only secure cipher modes are supported:
    - GCM: Galois/Counter Mode (authenticated encryption, recommended)
    - CBC: Cipher Block Chaining (legacy support only)
    
    Args:
        cipher_mode: String representation of cipher mode ('GCM' or 'CBC')
        
    Returns:
        AES mode constant (AES.MODE_GCM or AES.MODE_CBC)
        
    Raises:
        ValueError: If cipher_mode is not supported
    """
    mode_map = {
        'GCM': AES.MODE_GCM,
        'CBC': AES.MODE_CBC,
    }
    
    cipher_mode_upper = cipher_mode.upper()
    if cipher_mode_upper not in mode_map:
        raise ValueError(f'Unsupported cipher mode: {cipher_mode}. Only GCM and CBC are supported.')
    
    return mode_map[cipher_mode_upper]


def derive_key(passphrase: str) -> bytes:
    """
    Derive encryption key from passphrase using SHA-256.
    
    Args:
        passphrase: User passphrase
        
    Returns:
        SHA-256 digest of passphrase as bytes (32 bytes)
    """
    return SHA256.new(data=passphrase.encode('utf-8')).digest()


def derive_challenge(passphrase: str) -> bytes:
    """
    Derive challenge from passphrase.
    
    The challenge is the SHA-256 digest of the ones complement of the passphrase.
    
    Args:
        passphrase: User passphrase
        
    Returns:
        SHA-256 digest of ones-complemented passphrase as bytes (32 bytes)
    """
    challenge_string = ''
    for char in passphrase:
        challenge_string += chr(ord(char) ^ 0xff)
    return SHA256.new(data=challenge_string.encode('utf-8')).digest()


def generate_random_password() -> str:
    """
    Generate a random password.
    
    Returns:
        Base64-encoded random bytes as string (24 characters)
    """
    return b64encode(get_random_bytes(PASSWORD_LENGTH)).decode('utf-8')


def encrypt_data(data: bytes, encryption_key: bytes, cipher_mode: str = DEFAULT_CIPHER_MODE) -> dict:
    """
    Encrypt data using AES with specified mode.
    
    Args:
        data: Data to encrypt (bytes)
        encryption_key: Encryption key (32 bytes)
        cipher_mode: Cipher mode ('GCM' or 'CBC', default: GCM)
        
    Returns:
        Dictionary with keys:
        - 'iv': Base64-encoded IV/nonce
        - 'data': Base64-encoded encrypted data
        - 'tag': Base64-encoded authentication tag (GCM only)
    """
    iv = get_random_bytes(AES_BLOCK_SIZE)
    aes_mode = get_aes_mode(cipher_mode)
    
    if cipher_mode == 'GCM':
        cipher = AES.new(encryption_key, aes_mode, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }
    else:
        cipher = AES.new(encryption_key, aes_mode, iv=iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return {
            'iv': b64encode(iv).decode('utf-8'),
            'data': b64encode(ciphertext).decode('utf-8')
        }


def decrypt_data(encrypted_entry: dict, encryption_key: bytes, cipher_mode: str) -> bytes:
    """
    Decrypt data using AES with specified mode.
    
    Args:
        encrypted_entry: Dictionary with 'iv', 'data', and optionally 'tag' (for GCM)
        encryption_key: Decryption key (32 bytes)
        cipher_mode: Cipher mode ('GCM' or 'CBC')
        
    Returns:
        Decrypted data as bytes
        
    Raises:
        ValueError: If GCM mode is used without a tag, or if authentication fails
    """
    aes_mode = get_aes_mode(cipher_mode)
    iv = b64decode(encrypted_entry['iv'])
    data = b64decode(encrypted_entry['data'])
    
    if cipher_mode == 'GCM':
        if 'tag' not in encrypted_entry:
            raise ValueError('GCM mode requires authentication tag')
        cipher = AES.new(encryption_key, aes_mode, nonce=iv)
        decrypted = cipher.decrypt_and_verify(data, b64decode(encrypted_entry['tag']))
    else:
        cipher = AES.new(encryption_key, aes_mode, iv=iv)
        decrypted = cipher.decrypt(data)
        decrypted = unpad(decrypted, AES.block_size)
    
    return decrypted

