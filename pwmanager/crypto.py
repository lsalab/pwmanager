"""
Cryptographic operations for password manager.

Handles encryption, decryption, key derivation, and cryptographic utilities.
"""

import sys
# Try importing from Crypto (pycryptodome standard package)
# Fall back to Cryptodome (pycryptodomex or older installations)
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
except (ImportError, ModuleNotFoundError):
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Random import get_random_bytes
        from Cryptodome.Protocol.KDF import PBKDF2
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

# Key derivation constants
PBKDF2_ITERATIONS = 100000  # Recommended minimum for PBKDF2
PBKDF2_SALT_SIZE = 16  # 128 bits

# Cryptographic defaults
DEFAULT_CIPHER = 'AES'
DEFAULT_CIPHER_MODE = 'GCM'


def get_aes_mode(cipher_mode: str):
    """
    Convert cipher mode string to AES mode constant.
    
    Only GCM mode is supported (authenticated encryption).
    
    Args:
        cipher_mode: String representation of cipher mode ('GCM')
        
    Returns:
        AES mode constant (AES.MODE_GCM)
        
    Raises:
        ValueError: If cipher_mode is not GCM
    """
    cipher_mode_upper = cipher_mode.upper()
    if cipher_mode_upper != 'GCM':
        raise ValueError(f'Unsupported cipher mode: {cipher_mode}. Only GCM is supported.')
    
    return AES.MODE_GCM


def derive_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive encryption key from passphrase using PBKDF2.
    
    Args:
        passphrase: User passphrase
        salt: Salt bytes (typically 16 bytes)
        iterations: Number of PBKDF2 iterations (default: 100000)
        
    Returns:
        PBKDF2-derived key as bytes (32 bytes)
    """
    return PBKDF2(passphrase.encode('utf-8'), salt, dkLen=AES_KEY_SIZE, count=iterations)


def derive_challenge(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive challenge from passphrase using PBKDF2.
    
    The challenge uses PBKDF2 with the ones complement of the passphrase.
    
    Args:
        passphrase: User passphrase
        salt: Salt bytes (typically 16 bytes)
        iterations: Number of PBKDF2 iterations (default: 100000)
        
    Returns:
        PBKDF2-derived challenge as bytes (32 bytes)
    """
    challenge_string = ''
    for char in passphrase:
        challenge_string += chr(ord(char) ^ 0xff)
    return PBKDF2(challenge_string.encode('utf-8'), salt, dkLen=AES_KEY_SIZE, count=iterations)


def generate_random_password() -> str:
    """
    Generate a random password.
    
    Returns:
        Base64-encoded random bytes as string (24 characters)
    """
    return b64encode(get_random_bytes(PASSWORD_LENGTH)).decode('utf-8')


def encrypt_data(data: bytes, encryption_key: bytes, cipher_mode: str = DEFAULT_CIPHER_MODE) -> dict:
    """
    Encrypt data using AES-GCM.
    
    Args:
        data: Data to encrypt (bytes)
        encryption_key: Encryption key (32 bytes)
        cipher_mode: Cipher mode (default: GCM, only GCM is supported)
        
    Returns:
        Dictionary with keys:
        - 'iv': Base64-encoded nonce
        - 'data': Base64-encoded encrypted data
        - 'tag': Base64-encoded authentication tag
    """
    iv = get_random_bytes(AES_BLOCK_SIZE)
    aes_mode = get_aes_mode(cipher_mode)
    cipher = AES.new(encryption_key, aes_mode, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        'iv': b64encode(iv).decode('utf-8'),
        'data': b64encode(ciphertext).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt_data(encrypted_entry: dict, encryption_key: bytes, cipher_mode: str) -> bytes:
    """
    Decrypt data using AES-GCM.
    
    Args:
        encrypted_entry: Dictionary with 'iv', 'data', and 'tag'
        encryption_key: Decryption key (32 bytes)
        cipher_mode: Cipher mode (must be 'GCM')
        
    Returns:
        Decrypted data as bytes
        
    Raises:
        ValueError: If tag is missing or authentication fails
    """
    aes_mode = get_aes_mode(cipher_mode)
    iv = b64decode(encrypted_entry['iv'])
    data = b64decode(encrypted_entry['data'])
    
    if 'tag' not in encrypted_entry:
        raise ValueError('GCM mode requires authentication tag')
    cipher = AES.new(encryption_key, aes_mode, nonce=iv)
    decrypted = cipher.decrypt_and_verify(data, b64decode(encrypted_entry['tag']))
    
    return decrypted

