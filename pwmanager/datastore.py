"""
Datastore operations for password manager.

Handles loading, saving, and validation of password datastores.
Datastores use PBKDF2 key derivation with 100,000 iterations and GCM cipher mode
for authenticated encryption.
"""

import os
import shutil
from datetime import datetime
from json import dumps, loads
from base64 import b64encode, b64decode
from copy import deepcopy

from pwmanager.crypto import (
    get_aes_mode, derive_key, derive_challenge,
    encrypt_data, decrypt_data,
    AES, DEFAULT_CIPHER, DEFAULT_CIPHER_MODE,
    PBKDF2_ITERATIONS, PBKDF2_SALT_SIZE,
    AES_BLOCK_SIZE, get_random_bytes
)


def validate_store_path(path: str) -> bool:
    """
    Validate that the store path is safe to use.
    Prevents directory traversal and other path-based attacks.
    """
    if not path:
        return False
    
    dangerous_patterns = ['..', '/etc', '/proc', '/sys', '/dev']
    path_lower = path.lower()
    
    for pattern in dangerous_patterns:
        if pattern in path_lower:
            return False
    
    if path.startswith('/') and not path.startswith('./'):
        return False
    
    return True


def create_backup_file(store_path: str) -> str:
    """
    Create a backup of the datastore file with a timestamp.
    
    Args:
        store_path: Path to the datastore file to backup
        
    Returns:
        Path to the created backup file
        
    Raises:
        IOError: If the backup file cannot be created
    """
    if not os.path.exists(store_path):
        raise IOError(f'Datastore file not found: {store_path}')
    
    # Create backup filename with timestamp
    base_name = os.path.basename(store_path)
    dir_name = os.path.dirname(store_path)
    name_without_ext, ext = os.path.splitext(base_name)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f'{name_without_ext}_backup_{timestamp}{ext}'
    
    if dir_name:
        backup_path = os.path.join(dir_name, backup_filename)
    else:
        backup_path = backup_filename
    
    # Copy the file
    shutil.copy2(store_path, backup_path)
    print(f'Backup created: {backup_path}')
    
    return backup_path


def load_datastore(store_path: str) -> dict:
    """
    Load a datastore from file.
    
    Args:
        store_path: Path to the datastore file
        
    Returns:
        Datastore dictionary
        
    Raises:
        IOError: If the file cannot be read
    """
    with open(store_path, 'r') as f:
        return loads(f.read())


def save_datastore(datastore: dict, store_path: str = './data/store.pws'):
    """
    Save a datastore to file.
    
    Args:
        datastore: The datastore dictionary to save
        store_path: Path to save the datastore file
    """
    with open(store_path, 'w') as store_file:
        store_file.write(dumps(datastore, indent=2))
        store_file.flush()
        print('Datastore saved!')


def verify_passphrase(datastore: dict, passphrase: str) -> bool:
    """
    Verify passphrase by decrypting and checking challenge.
    
    Uses PBKDF2 to derive the encryption key and challenge, then verifies by decrypting the stored challenge.
    
    Args:
        datastore: The datastore dictionary
        passphrase: The passphrase to verify
        
    Returns:
        True if passphrase is correct, False otherwise
        
    Raises:
        ValueError: If decryption fails, cipher mode is invalid, or salt/iterations are missing
    """
    if 'salt' not in datastore or 'iterations' not in datastore:
        raise ValueError('PBKDF2 datastore missing salt or iterations')
    
    salt = b64decode(datastore['salt'])
    iterations = datastore.get('iterations', PBKDF2_ITERATIONS)
    encryption_key = derive_key(passphrase, salt, iterations)
    challenge = derive_challenge(passphrase, salt, iterations)
    
    iv = b64decode(datastore['iv'])
    cipher_mode = datastore.get('cipher_mode', DEFAULT_CIPHER_MODE)
    aes_mode = get_aes_mode(cipher_mode)
    challenge_encrypted = b64decode(datastore['challenge'])
    
    cipher = AES.new(encryption_key, aes_mode, nonce=iv)
    if 'tag' not in datastore:
        raise ValueError('GCM mode requires authentication tag')
    try:
        challenge_decrypted = cipher.decrypt_and_verify(challenge_encrypted, b64decode(datastore['tag']))
    except ValueError:
        return False
    
    return challenge == challenge_decrypted


def get_encryption_key_from_datastore(datastore: dict, passphrase: str) -> bytes:
    """
    Get encryption key from datastore using PBKDF2.
    
    Args:
        datastore: The datastore dictionary
        passphrase: The passphrase
        
    Returns:
        Encryption key as bytes (32 bytes)
        
    Raises:
        ValueError: If salt or iterations are missing
    """
    if 'salt' not in datastore:
        raise ValueError('PBKDF2 datastore missing salt')
    salt = b64decode(datastore['salt'])
    iterations = datastore.get('iterations', PBKDF2_ITERATIONS)
    return derive_key(passphrase, salt, iterations)


def initialize_datastore(store_path: str, passphrase: str):
    """
    Initialize a new datastore with the given passphrase.
    
    The datastore is created with the default cryptographic parameters:
    - Cipher: AES (as specified by DEFAULT_CIPHER)
    - Mode: GCM by default (as specified by DEFAULT_CIPHER_MODE)
    - Key Derivation: PBKDF2
    
    Args:
        store_path: Path where to create the datastore
        passphrase: Passphrase to encrypt the datastore with
    """
    # Generate salt for PBKDF2
    salt = get_random_bytes(PBKDF2_SALT_SIZE)
    
    # Derive key and challenge using PBKDF2
    encryption_key = derive_key(passphrase, salt, PBKDF2_ITERATIONS)
    challenge = derive_challenge(passphrase, salt, PBKDF2_ITERATIONS)
    
    config_data = {
        'store': {},
        'iv': b64encode(get_random_bytes(AES_BLOCK_SIZE)).decode('utf-8'),
        'cipher': DEFAULT_CIPHER,
        'cipher_mode': DEFAULT_CIPHER_MODE,
        'key_derivation': 'PBKDF2',
        'salt': b64encode(salt).decode('utf-8'),
        'iterations': PBKDF2_ITERATIONS
    }
    
    encrypted_challenge = encrypt_data(challenge, encryption_key, DEFAULT_CIPHER_MODE)
    config_data['challenge'] = encrypted_challenge['data']
    if 'tag' in encrypted_challenge:
        config_data['tag'] = encrypted_challenge['tag']
    
    data_dir = os.path.dirname(store_path)
    if data_dir and not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    save_datastore(config_data, store_path)


def decrypt_entry(entry: dict, encryption_key: bytes, cipher_mode: str) -> dict:
    """
    Decrypt a single password entry using AES-GCM.
    
    Args:
        entry: Dictionary containing 'iv', 'data', and 'tag'
        encryption_key: The decryption key (derived from passphrase)
        cipher_mode: The cipher mode string (must be 'GCM')
        
    Returns:
        Decrypted entry data as dictionary with 'username' and 'password'
        
    Raises:
        ValueError: If tag is missing or authentication fails
    """
    entry_data = decrypt_data(entry, encryption_key, cipher_mode)
    return loads(entry_data.decode('utf-8'))


def encrypt_entry(username: str, password: str, encryption_key: bytes, cipher_mode: str) -> dict:
    """
    Encrypt a password entry using AES-GCM.
    
    Args:
        username: Username to encrypt
        password: Password to encrypt
        encryption_key: Encryption key (derived from passphrase)
        cipher_mode: Cipher mode string (must be 'GCM')
        
    Returns:
        Encrypted entry dictionary with 'iv', 'data', and 'tag'
    """
    from json import dumps
    entry_data = {'username': username, 'password': password}
    entry_data_json = dumps(entry_data).encode('utf-8')
    return encrypt_data(entry_data_json, encryption_key, cipher_mode)
