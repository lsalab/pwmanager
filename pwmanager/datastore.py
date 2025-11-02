"""
Datastore operations for password manager.

Handles loading, saving, migration, and validation of password datastores.
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
    AES, LEGACY_CIPHER, LEGACY_CIPHER_MODE, DEFAULT_CIPHER, DEFAULT_CIPHER_MODE,
    PBKDF2_ITERATIONS, PBKDF2_SALT_SIZE,
    AES_BLOCK_SIZE, get_random_bytes
)
# Import pad and unpad from Crypto - needed for migration operations
try:
    from Crypto.Util.Padding import pad as pad_util, unpad as unpad_util
except ImportError:
    from Cryptodome.Util.Padding import pad as pad_util, unpad as unpad_util


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


def migrate_legacy_datastore(datastore: dict) -> bool:
    """
    Migrate legacy datastores by adding cryptographic parameters.
    
    Detects legacy datastores (those without 'cipher' or 'cipher_mode' keys)
    and adds them with the current legacy values (AES, CBC).
    
    Args:
        datastore: The datastore dictionary to check and potentially migrate
        
    Returns:
        True if the datastore was migrated (was legacy), False otherwise
    """
    was_legacy = False
    
    # Check for missing cipher/cipher_mode (old legacy)
    if 'cipher' not in datastore or 'cipher_mode' not in datastore:
        was_legacy = True
        datastore['cipher'] = LEGACY_CIPHER
        datastore['cipher_mode'] = LEGACY_CIPHER_MODE
        print('Legacy datastore detected. Added cryptographic parameters (cipher: AES, cipher_mode: CBC)')
    
    return was_legacy


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
    cipher_mode = datastore.get('cipher_mode', LEGACY_CIPHER_MODE)
    aes_mode = get_aes_mode(cipher_mode)
    challenge_encrypted = b64decode(datastore['challenge'])
    
    if cipher_mode == 'GCM':
        cipher = AES.new(encryption_key, aes_mode, nonce=iv)
        if 'tag' not in datastore:
            raise ValueError('GCM mode requires authentication tag')
        try:
            challenge_decrypted = cipher.decrypt_and_verify(challenge_encrypted, b64decode(datastore['tag']))
        except ValueError:
            return False
    else:
        cipher = AES.new(encryption_key, aes_mode, iv=iv)
        challenge_decrypted = cipher.decrypt(challenge_encrypted)
        try:
            challenge_decrypted = unpad_util(challenge_decrypted, AES.block_size)
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
    Decrypt a single password entry.
    
    Supports multiple cipher modes:
    - GCM mode: Requires authentication tag, uses decrypt_and_verify
    - CBC and other modes: Uses standard decrypt with unpadding
    
    Args:
        entry: Dictionary containing 'iv', 'data', and optionally 'tag' (for GCM)
        encryption_key: The decryption key (derived from passphrase)
        cipher_mode: The cipher mode string (e.g., 'GCM', 'CBC')
        
    Returns:
        Decrypted entry data as dictionary with 'username' and 'password'
        
    Raises:
        ValueError: If GCM mode is used without a tag, or if authentication fails
    """
    entry_data = decrypt_data(entry, encryption_key, cipher_mode)
    return loads(entry_data.decode('utf-8'))


def encrypt_entry(username: str, password: str, encryption_key: bytes, cipher_mode: str) -> dict:
    """
    Encrypt a password entry.
    
    Args:
        username: Username to encrypt
        password: Password to encrypt
        encryption_key: Encryption key (derived from passphrase)
        cipher_mode: Cipher mode string (e.g., 'GCM', 'CBC')
        
    Returns:
        Encrypted entry dictionary with 'iv', 'data', and optionally 'tag'
    """
    from json import dumps
    entry_data = {'username': username, 'password': password}
    entry_data_json = dumps(entry_data).encode('utf-8')
    return encrypt_data(entry_data_json, encryption_key, cipher_mode)

def migrate_datastore_to_gcm(store_path: str, encryption_key: bytes, passphrase: str = None) -> bool:
    """
    Migrate a CBC (legacy) datastore to GCM mode.
    
    This function:
    1. Loads the datastore and verifies it uses CBC mode
    2. Creates a backup of the original file
    3. Decrypts all entries using CBC mode
    4. Re-encrypts all entries and challenge using GCM mode
    5. Updates the datastore metadata
    6. Saves the migrated datastore
    
    Args:
        store_path: Path to the datastore file to migrate
        encryption_key: The encryption key (derived from passphrase)
        passphrase: Optional passphrase for challenge verification (if None, uses existing challenge)
        
    Returns:
        True if migration was successful, False if the datastore is already in GCM mode
        
    Raises:
        ValueError: If the datastore is not in CBC mode or if decryption fails
        IOError: If the file cannot be read or written
    """
    if not os.path.exists(store_path):
        raise IOError(f'Datastore file not found: {store_path}')
    
    # Load the datastore
    datastore = load_datastore(store_path)
    
    # Ensure legacy datastores have cipher/cipher_mode
    migrate_legacy_datastore(datastore)
    
    # Check if already in GCM mode
    current_mode = datastore.get('cipher_mode', LEGACY_CIPHER_MODE)
    if current_mode == 'GCM':
        print(f'Datastore at {store_path} is already in GCM mode. No migration needed.')
        return False
    
    if current_mode != 'CBC':
        raise ValueError(f'Unsupported cipher mode for migration: {current_mode}. Only CBC can be migrated to GCM.')
    
    print(f'Migrating datastore from CBC to GCM mode: {store_path}')
    
    # Create backup
    backup_path = create_backup_file(store_path)
    
    try:
        # Decrypt the challenge using CBC to verify the key is correct
        old_iv = b64decode(datastore['iv'])
        old_challenge_encrypted = b64decode(datastore['challenge'])
        old_aes_mode = get_aes_mode('CBC')
        old_cipher = AES.new(encryption_key, old_aes_mode, iv=old_iv)
        old_challenge = old_cipher.decrypt(old_challenge_encrypted)
        old_challenge = unpad_util(old_challenge, AES.block_size)
        
        # If passphrase is provided, verify it
        if passphrase:
            if 'salt' not in datastore:
                raise ValueError('PBKDF2 datastore missing salt')
            salt = b64decode(datastore['salt'])
            iterations = datastore.get('iterations', PBKDF2_ITERATIONS)
            expected_challenge = derive_challenge(passphrase, salt, iterations)
            
            if expected_challenge != old_challenge:
                raise ValueError('Passphrase verification failed. Incorrect passphrase.')
        
        # Migrate challenge to GCM
        new_iv = get_random_bytes(AES_BLOCK_SIZE)
        new_aes_mode = get_aes_mode('GCM')
        new_cipher = AES.new(encryption_key, new_aes_mode, nonce=new_iv)
        new_challenge_ciphertext, new_challenge_tag = new_cipher.encrypt_and_digest(old_challenge)
        
        # Update challenge in datastore
        datastore['iv'] = b64encode(new_iv).decode('utf-8')
        datastore['challenge'] = b64encode(new_challenge_ciphertext).decode('utf-8')
        datastore['tag'] = b64encode(new_challenge_tag).decode('utf-8')
        
        # Migrate all entries from CBC to GCM
        migrated_entries = {}
        for site_name, entry in datastore['store'].items():
            # Decrypt entry using CBC
            entry_iv = b64decode(entry['iv'])
            entry_data_encrypted = b64decode(entry['data'])
            entry_cipher_old = AES.new(encryption_key, old_aes_mode, iv=entry_iv)
            entry_data_decrypted = entry_cipher_old.decrypt(entry_data_encrypted)
            entry_data_decrypted = unpad_util(entry_data_decrypted, AES.block_size)
            
            # Re-encrypt entry using GCM
            new_entry_iv = get_random_bytes(AES_BLOCK_SIZE)
            entry_cipher_new = AES.new(encryption_key, new_aes_mode, nonce=new_entry_iv)
            entry_data_reencrypted, entry_tag = entry_cipher_new.encrypt_and_digest(entry_data_decrypted)
            
            # Update entry
            migrated_entries[site_name] = {
                'iv': b64encode(new_entry_iv).decode('utf-8'),
                'data': b64encode(entry_data_reencrypted).decode('utf-8'),
                'tag': b64encode(entry_tag).decode('utf-8')
            }
        
        # Update datastore with migrated entries and metadata
        datastore['store'] = migrated_entries
        datastore['cipher'] = DEFAULT_CIPHER
        datastore['cipher_mode'] = DEFAULT_CIPHER_MODE
        
        # Save migrated datastore
        save_datastore(datastore, store_path)
        print(f'Successfully migrated datastore to GCM mode. Backup saved at: {backup_path}')
        
        return True
        
    except Exception as e:
        # If migration fails, restore from backup
        print(f'Migration failed: {str(e)}')
        print(f'Restoring from backup: {backup_path}')
        shutil.copy2(backup_path, store_path)
        raise
