#!/usr/bin/env python3
# pylint: disable=line-too-long
"""
Simple password manager with support for multiple cryptographic modes.

This password manager stores website passwords encrypted with AES-256.
It supports two secure cipher modes:
- GCM (Galois/Counter Mode): Default for new datastores, provides authenticated encryption
- CBC (Cipher Block Chaining): Legacy mode, supported for backward compatibility

The encryption key is derived from a user passphrase using SHA-256.
Each datastore includes cryptographic parameters (cipher and mode) for flexibility.
"""

import os
import sys
import argparse
import getpass
import shutil
from datetime import datetime
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as mbox
from json import dumps, loads
from base64 import b64encode, b64decode
from copy import deepcopy
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

PW_ADD = 0
PW_DEL = 1
PW_EDT = 2
CB_USER = 0
CB_PASS = 1

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

def migrate_legacy_datastore(datastore: dict) -> bool:
    """
    Migrate legacy datastores by adding cryptographic parameters.
    
    Detects legacy datastores (those without 'cipher' and 'cipher_mode' keys)
    and adds them with the current legacy values (AES, CBC).
    
    Args:
        datastore: The datastore dictionary to check and potentially migrate
        
    Returns:
        True if the datastore was migrated (was legacy), False otherwise
    """
    was_legacy = False
    
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
        encryption_key: The encryption key (SHA-256 digest of passphrase)
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
    with open(store_path, 'r') as f:
        datastore = loads(f.read())
    
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
        old_challenge = unpad(old_challenge, AES.block_size)
        
        # If passphrase is provided, verify it
        if passphrase:
            challenge_string = ''
            for char in passphrase:
                challenge_string += chr(ord(char) ^ 0xff)
            expected_challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
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
            entry_data_decrypted = unpad(entry_data_decrypted, AES.block_size)
            
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
        saveDatastore(datastore, store_path)
        print(f'Successfully migrated datastore to GCM mode. Backup saved at: {backup_path}')
        
        return True
        
    except Exception as e:
        # If migration fails, restore from backup
        print(f'Migration failed: {str(e)}')
        print(f'Restoring from backup: {backup_path}')
        shutil.copy2(backup_path, store_path)
        raise

class InitialConfig():
    """
    Initial configuration dialog
    """

    def __init__(self, parent, store_path=None):
        self.store_path = store_path if store_path else './data/store.pws'
        dialog_window = self.top = tk.Toplevel(parent)
        dialog_window.resizable(width=False, height=False)
        tk.Label(dialog_window, text='Datastore must be initialized and locked').grid(
            row=0,
            column=0,
            columnspan=2,
            padx=2,
            pady=2
        )
        tk.Label(dialog_window, text="Enter passphrase:").grid(
            row=1,
            column=0,
            padx=2,
            sticky=tk.W
        )
        passphrase_entry1 = self.pp1 = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry1.grid(
            row=1,
            column=1,
            sticky=tk.E
        )
        passphrase_entry1.bind('<Key>', self.verify)
        tk.Label(dialog_window, text="Re-enter passphrase:").grid(
            row=2,
            column=0,
            padx=2,
            sticky=tk.W
        )
        passphrase_entry2 = self.pp2 = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry2.grid(
            row=2,
            column=1,
            sticky=tk.E
        )
        passphrase_entry2.bind('<Key>', self.verify)
        status_label = self.ppstat = tk.Label(dialog_window, text='', fg='red')
        status_label.grid(
            row=3,
            column=0,
            columnspan=2
        )
        ok_button = self.okbtn = tk.Button(dialog_window, text="OK", command=self.ok, state=tk.DISABLED)
        ok_button.grid(
            row=4,
            column=0,
            columnspan=2,
            padx=2,
            pady=2
        )
        self.key = None
        self.challenge = None
        dialog_window.grab_set()
        dialog_window.attributes('-topmost', True)
        dialog_window.protocol('WM_DELETE_WINDOW', self.ok)

    def verify(self, event):
        """
        Checks whether both passphrases are the same
        
        Compares both fields after each keystroke to ensure they match.
        Note: This checks mid-typing, so there may be momentary mismatch states.
        """
        passphrase1 = self.pp1.get()
        passphrase2 = self.pp2.get()
        
        if passphrase1 and passphrase2 and passphrase1 == passphrase2:
            self.okbtn.config(state=tk.NORMAL)
            self.ppstat.config(text='')
        else:
            self.okbtn.config(state=tk.DISABLED)
            if passphrase1 and passphrase2 and len(passphrase1) == len(passphrase2):
                self.ppstat.config(text='Passphrase does not match')
            else:
                self.ppstat.config(text='')

    def ok(self):
        """
        Creates (if needed) the datastore and locks it with the given passphrase.

        The datastore is created with the default cryptographic parameters:
        - Cipher: AES (as specified by DEFAULT_CIPHER)
        - Mode: GCM by default (as specified by DEFAULT_CIPHER_MODE)

        Encryption key is the SHA256 digest of passphrase, as bytes.

        A challenge is generated as the SHA256 digest of the ones complement of the passphrase.
        The challenge is encrypted using the cipher and mode specified in the datastore
        (GCM mode uses authentication tags, CBC mode uses padding).

        For GCM mode:
        Challenge = AES256-GCM(IV, Key, SHA256(CONCAT(i XOR 0xFF for i in passphrase)))
        Includes authentication tag for tamper detection.

        For CBC mode:
        Challenge = AES256-CBC(IV, Key, SHA256(CONCAT(i XOR 0xFF for i in passphrase)))
        Uses PKCS padding.
        """
        config_data = {}
        config_data['store'] = {}
        passphrase = self.pp1.get()
        self.key = SHA256.new(data=passphrase.encode('utf-8')).digest()
        challenge_string = ''
        for char in passphrase:
            challenge_string += chr(ord(char) ^ 0xff)
        self.challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
        initialization_vector = get_random_bytes(AES_BLOCK_SIZE)
        config_data['iv'] = b64encode(initialization_vector).decode('utf-8')
        config_data['cipher'] = DEFAULT_CIPHER
        config_data['cipher_mode'] = DEFAULT_CIPHER_MODE
        aes_mode = get_aes_mode(config_data['cipher_mode'])
        
        if config_data['cipher_mode'] == 'GCM':
            cipher = AES.new(self.key, aes_mode, nonce=initialization_vector)
            ciphertext, tag = cipher.encrypt_and_digest(self.challenge)
            config_data['challenge'] = b64encode(ciphertext).decode('utf-8')
            config_data['tag'] = b64encode(tag).decode('utf-8')
        else:
            cipher = AES.new(self.key, aes_mode, iv=initialization_vector)
            config_data['challenge'] = b64encode(cipher.encrypt(pad(self.challenge, AES.block_size))).decode('utf-8')
        
        data_dir = os.path.dirname(self.store_path)
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        with open(self.store_path, 'w') as config_file:
            config_file.write(dumps(config_data, indent=2))
        self.top.grab_release()
        self.top.destroy()

class AskPassphrase():
    """
    Dialog window used to unlock the datastore.
    """

    def __init__(self, parent):
        dialog_window = self.top = tk.Toplevel(parent)
        dialog_window.resizable(width=False, height=False)
        tk.Label(dialog_window, text="Enter passphrase:").grid(
            row=0,
            column=0,
            padx=2,
            pady=2
        )
        passphrase_entry = self.pp = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry.grid(row=1, column=0, padx=2, pady=2)
        ok_button = self.okbtn = tk.Button(dialog_window, text="OK", command=self.ok)
        ok_button.grid(row=4, column=0, columnspan=2, padx=2, pady=2)
        self.__key = b''
        self.__challenge = b''
        passphrase_entry.focus_set()
        passphrase_entry.bind('<Return>', self.ok)
        dialog_window.grab_set()
        dialog_window.attributes('-topmost', True)
        dialog_window.protocol('WM_DELETE_WINDOW', self.ok)

    @property
    def key(self) -> bytes:
        return self.__key

    @key.setter
    def key(self, value: bytes):
        if value is not None and isinstance(value, bytes):
            self.__key = value

    @property
    def challenge(self) -> bytes:
        return self.__challenge

    @challenge.setter
    def challenge(self, value: bytes):
        if value is not None and isinstance(value, bytes):
            self.__challenge = value

    def ok(self, event=None): # pylint: disable=unused-argument
        if self.pp.get():
            passphrase = self.pp.get()
            self.__key = SHA256.new(data=passphrase.encode('utf-8')).digest()
            challenge_string = ''
            for char in passphrase:
                challenge_string += chr(ord(char) ^ 0xff)
            self.__challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
            self.top.grab_release()
            self.top.destroy()

class MigrateDialog():
    """
    Dialog window used to migrate a CBC datastore to GCM mode.
    """

    def __init__(self, parent):
        dialog_window = self.top = tk.Toplevel(parent)
        dialog_window.resizable(width=False, height=False)
        dialog_window.title('Migrate to GCM Mode')
        
        tk.Label(dialog_window, 
                text="This datastore is using legacy CBC encryption.\n"
                     "Migrate to GCM mode for enhanced security?\n\n"
                     "A backup will be created automatically.",
                justify=tk.LEFT).grid(
            row=0,
            column=0,
            columnspan=2,
            padx=10,
            pady=10
        )
        
        tk.Label(dialog_window, text="Enter passphrase:").grid(
            row=1,
            column=0,
            padx=2,
            pady=2,
            sticky=tk.W
        )
        passphrase_entry = self.pp = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry.grid(row=1, column=1, padx=2, pady=2)
        
        self.status_label = tk.Label(dialog_window, text='', fg='red')
        self.status_label.grid(row=2, column=0, columnspan=2, padx=2, pady=2)
        
        button_frame = tk.Frame(dialog_window)
        button_frame.grid(row=3, column=0, columnspan=2, padx=2, pady=10)
        
        ok_button = tk.Button(button_frame, text="Migrate", command=self.ok, width=10)
        ok_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = tk.Button(button_frame, text="Cancel", command=self.cancel, width=10)
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        self.passphrase = None
        self.migrated = False
        passphrase_entry.focus_set()
        passphrase_entry.bind('<Return>', self.ok)
        dialog_window.grab_set()
        dialog_window.attributes('-topmost', True)
        dialog_window.protocol('WM_DELETE_WINDOW', self.cancel)

    def ok(self, event=None): # pylint: disable=unused-argument
        if self.pp.get():
            self.passphrase = self.pp.get()
            self.top.grab_release()
            self.top.destroy()
        else:
            self.status_label.config(text='Please enter passphrase', fg='red')

    def cancel(self):
        self.passphrase = None
        self.top.grab_release()
        self.top.destroy()

class PWDiag(): # pylint: disable=too-many-instance-attributes
    """Password information dialog"""

    def __init__(self, parent, **kwargs):
        top = self.top = tk.Toplevel(master=parent)
        self.__site = tk.StringVar(master=top)
        self.__username = tk.StringVar(master=top)
        self.__password = tk.StringVar(master=top)
        self.__okpressed = False
        tk.Label(master=top, text='Site:').grid(
            row=0, column=0,
            padx=2, pady=2
        )
        se = self.se = tk.Entry(master=top, width=32, textvariable=self.__site)
        se.grid(row=0, column=1, columnspan=2, padx=2, pady=2)
        se.bind('<Return>', self.ok)
        tk.Label(master=top, text='Username:').grid(
            row=1, column=0,
            padx=2, pady=2
        )
        ue = self.ue = tk.Entry(master=top, width=32, textvariable=self.__username)
        ue.grid(row=1, column=1, columnspan=2, padx=2, pady=2)
        ue.bind('<Return>', self.ok)
        tk.Label(master=top, text='Password:').grid(
            row=2, column=0,
            padx=2, pady=2
        )
        pe = self.pe = tk.Entry(master=top, width=32, textvariable=self.__password)
        pe.grid(row=2, column=1, columnspan=2, padx=2, pady=2)
        pe.bind('<Return>', self.ok)
        pe.bind('<FocusIn>', lambda evt: self.pe.config(show=''))
        pe.bind('<FocusOut>', lambda evt: self.pe.config(show='*'))
        okbtn = self.okbtn = tk.Button(top, text="OK", command=self.ok)
        okbtn.grid(row=3, column=2, columnspan=1, padx=10, pady=2, sticky='ew')
        genbtn = self.genbtn = tk.Button(top, text="Generate", command=self.__generate)
        genbtn.grid(row=3, column=1, columnspan=1, padx=2, pady=2, sticky='ew')
        if 'site' in kwargs:
            self.__site.set(kwargs['site'])
        if 'username' in kwargs:
            self.__username.set(kwargs['username'])
        if 'password' in kwargs:
            self.__password.set(kwargs['password'])
        top.grab_set()
        top.attributes('-topmost', True)
        se.focus_set()
        top.protocol('WM_DELETE_WINDOW', self.__done)

    @property
    def site(self) -> str:
        return str(self.__site.get())

    @site.setter
    def site(self, value: str):
        if value is not None and isinstance(value, str):
            self.__site.set(value)
        else:
            self.__site.set('')

    @property
    def username(self) -> str:
        return str(self.__username.get())

    @username.setter
    def username(self, value: str):
        if value is not None and isinstance(value, str):
            self.__username.set(value)
        else:
            self.__username.set('')

    @property
    def password(self) -> str:
        return str(self.__password.get())

    @password.setter
    def password(self, value: str):
        if value is not None and isinstance(value, str):
            self.__password.set(value)
        else:
            self.__password.set('')

    @property
    def okpressed(self) -> bool:
        return self.__okpressed
    
    @okpressed.setter
    def okpressed(self, value: bool=False):
        self.__okpressed = value

    def __done(self, event=None):
        self.top.grab_release()
        self.top.destroy()

    def __generate(self):
        self.password = b64encode(get_random_bytes(PASSWORD_LENGTH)).decode('utf-8')

    def ok(self, event=None): # pylint: disable=unused-argument
        self.__okpressed = True
        self.__done()

def handlePw(master: tk.Tk, datastore: dict, key: bytes, guilist: ttk.Treeview, action: int):
    if action in [PW_ADD, PW_EDT]:
        password_dialog = None
        if action == PW_ADD:
            password_dialog = PWDiag(master)
        else:
            if guilist.focus() == '':
                return
            selected_item_id = guilist.selection()[0]
            selected_item = guilist.item(selected_item_id)
            selected_values = selected_item['values']
            old_site = selected_values[0]
            old_username = selected_values[1]
            old_password = selected_values[2]
            password_dialog = PWDiag(master, site=deepcopy(old_site), username=deepcopy(old_username), password=deepcopy(old_password))
            password_dialog.se.config(state=tk.DISABLED)
            password_dialog.ue.config(state=tk.DISABLED)
            password_dialog.pe.focus_set()
            guilist.delete(selected_item_id)
            del old_site
            del old_username
            del old_password
            del selected_values
        master.wait_window(password_dialog.top)
        if password_dialog.okpressed and password_dialog.site.strip() != '':
            datastore.pop(password_dialog.site, None)
            entry = {}
            entry_initialization_vector = get_random_bytes(AES_BLOCK_SIZE)
            cipher_mode = datastore['cipher_mode']
            aes_mode = get_aes_mode(cipher_mode)
            entry['iv'] = b64encode(entry_initialization_vector).decode('utf-8')
            entry_data = {}
            entry_data['username'] = password_dialog.username
            entry_data['password'] = password_dialog.password
            entry_data_json = dumps(entry_data).encode('utf-8')
            
            if cipher_mode == 'GCM':
                entry_cipher = AES.new(key, aes_mode, nonce=entry_initialization_vector)
                entry_data_encrypted, tag = entry_cipher.encrypt_and_digest(entry_data_json)
                entry['data'] = b64encode(entry_data_encrypted).decode('utf-8')
                entry['tag'] = b64encode(tag).decode('utf-8')
            else:
                entry_cipher = AES.new(key, aes_mode, iv=entry_initialization_vector)
                entry_data_encrypted = entry_cipher.encrypt(pad(entry_data_json, AES.block_size))
                entry['data'] = b64encode(entry_data_encrypted).decode('utf-8')
            
            datastore['store'][password_dialog.site] = deepcopy(entry)
            guilist.insert('', tk.END, values=(deepcopy(password_dialog.site), deepcopy(password_dialog.username), deepcopy(password_dialog.password)))
    elif action == PW_DEL:
        if guilist.focus() == '':
            return
        selected_item_id = guilist.selection()[0]
        site_name = guilist.item(selected_item_id)['values'][0]
        if mbox.askyesno(title='Delete password', message='Are you sure you want to delete the selected password?\r\n(This cannot be undone)'):
            datastore['store'].pop(site_name, None)
            guilist.delete(selected_item_id)
    else:
        print('ERROR: Unknown action')

def saveDatastore(datastore: dict, store_path='./data/store.pws'):
    with open(store_path, 'w') as store_file:
        store_file.write(dumps(datastore, indent=2))
        store_file.flush()
        print('Datastore saved!')

def saveAndExit(datastore: dict, store_path='./data/store.pws'):
    saveDatastore(datastore, store_path)
    sys.exit(0)

def copyToClipboard(master: tk.Tk, listbox: ttk.Treeview, val: int):
    if listbox.focus() == '':
        return
    itemid = listbox.selection()[0]
    values = listbox.item(itemid)['values']
    master.clipboard_clear()
    if val == CB_USER:
        master.clipboard_append(values[1])
    elif val == CB_PASS:
        master.clipboard_append(values[2])
    else:
        print('Unknown header')
    master.update()

def searchCallback(datastore: dict, encryption_key:bytes, guilist: ttk.Treeview, search_var: tk.StringVar):
    for child in guilist.get_children():
        guilist.delete(child)
    cipher_mode = datastore['cipher_mode']
    aes_mode = get_aes_mode(cipher_mode)
    for site_name in [x for x in datastore['store'].keys() if search_var.get().lower() in x.lower()]:
        entry = deepcopy(datastore['store'][site_name])
        
        if cipher_mode == 'GCM':
            entry_cipher = AES.new(encryption_key, aes_mode, nonce=b64decode(entry['iv']))
            if 'tag' not in entry:
                continue
            entry_data = entry_cipher.decrypt_and_verify(b64decode(entry['data']), b64decode(entry['tag']))
        else:
            entry_cipher = AES.new(encryption_key, aes_mode, iv=b64decode(entry['iv']))
            entry_data = entry_cipher.decrypt(b64decode(entry['data']))
            entry_data = unpad(entry_data, AES.block_size)
        
        entry_data = loads(entry_data.decode('utf-8'))
        guilist.insert('', tk.END, values=(deepcopy(site_name), deepcopy(entry_data['username']), deepcopy(entry_data['password'])))

def decryptEntry(entry: dict, encryption_key: bytes, cipher_mode: str) -> dict:
    """
    Decrypt a single password entry.
    
    Supports multiple cipher modes:
    - GCM mode: Requires authentication tag, uses decrypt_and_verify
    - CBC and other modes: Uses standard decrypt with unpadding
    
    Args:
        entry: Dictionary containing 'iv', 'data', and optionally 'tag' (for GCM)
        encryption_key: The decryption key (SHA-256 digest of passphrase)
        cipher_mode: The cipher mode string (e.g., 'GCM', 'CBC')
        
    Returns:
        Decrypted entry data as dictionary with 'username' and 'password'
        
    Raises:
        ValueError: If GCM mode is used without a tag, or if authentication fails
    """
    aes_mode = get_aes_mode(cipher_mode)
    
    if cipher_mode == 'GCM':
        if 'tag' not in entry:
            raise ValueError('GCM mode requires authentication tag')
        entry_cipher = AES.new(encryption_key, aes_mode, nonce=b64decode(entry['iv']))
        entry_data = entry_cipher.decrypt_and_verify(b64decode(entry['data']), b64decode(entry['tag']))
    else:
        entry_cipher = AES.new(encryption_key, aes_mode, iv=b64decode(entry['iv']))
        entry_data = entry_cipher.decrypt(b64decode(entry['data']))
        entry_data = unpad(entry_data, AES.block_size)
    
    entry_data = loads(entry_data.decode('utf-8'))
    return entry_data

def displayTerminal(datastore: dict, encryption_key: bytes, search_term: str = None):
    """
    Display passwords in terminal mode.
    
    Decrypts all entries using the datastore's specified cipher mode
    (supports GCM with authentication tags and CBC with padding).
    
    Args:
        datastore: The datastore dictionary containing entries and cipher_mode
        encryption_key: The decryption key (SHA-256 digest of passphrase)
        search_term: Optional search term to filter entries by site name
    """
    print("\n" + "="*80)
    print(" PASSWORD MANAGER - DATASTORE ENTRIES")
    print("="*80)
    
    entries = []
    cipher_mode = datastore['cipher_mode']
    for site_name in sorted(datastore['store'].keys()):
        if search_term is None or search_term.lower() in site_name.lower():
            entry_data = decryptEntry(datastore['store'][site_name], encryption_key, cipher_mode)
            entries.append({
                'site': site_name,
                'username': entry_data['username'],
                'password': entry_data['password']
            })
    
    if not entries:
        if search_term:
            print(f"\nNo entries found matching '{search_term}'")
        else:
            print("\nNo entries found in datastore")
        return
    
    max_site = max(len(e['site']) for e in entries)
    max_user = max(len(e['username']) for e in entries)
    max_pass = max(len(e['password']) for e in entries)
    
    col_site = max(20, max_site + 2)
    col_user = max(20, max_user + 2)
    col_pass = max(20, max_pass + 2)
    
    print(f"\n{'Site':<{col_site}} {'Username':<{col_user}} {'Password':<{col_pass}}")
    print("-" * (col_site + col_user + col_pass))
    
    for entry in entries:
        print(f"{entry['site']:<{col_site}} {entry['username']:<{col_user}} {entry['password']:<{col_pass}}")
    
    print(f"\nTotal entries: {len(entries)}")
    print("="*80 + "\n")

def terminalMode(store_path: str, search_term: str = None):
    """
    Run password manager in terminal mode.
    
    Loads and unlocks a datastore, then displays entries. Supports both
    GCM and CBC cipher modes. Legacy datastores are automatically migrated
    to include cryptographic parameters.
    
    Args:
        store_path: Path to the datastore file
        search_term: Optional search term to filter displayed entries
    """
    if not os.path.exists(store_path):
        sys.stderr.write(f"ERROR: Datastore not found at {store_path}\n")
        sys.exit(1)
    
    try:
        passphrase = getpass.getpass("Enter passphrase: ")
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)
    
    encryption_key = SHA256.new(data=passphrase.encode('utf-8')).digest()
    challenge_string = ''
    for char in passphrase:
        challenge_string += chr(ord(char) ^ 0xff)
    expected_challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
    
    try:
        with open(store_path, 'r') as store_file:
            datastore = loads(store_file.read())
        
        was_migrated = migrate_legacy_datastore(datastore)
        if was_migrated:
            saveDatastore(datastore, store_path)
        
        initialization_vector = b64decode(datastore['iv'])
        cipher_mode = datastore['cipher_mode']
        aes_mode = get_aes_mode(cipher_mode)
        challenge_encrypted = b64decode(datastore['challenge'])
        
        if cipher_mode == 'GCM':
            cipher = AES.new(encryption_key, aes_mode, nonce=initialization_vector)
            if 'tag' not in datastore:
                raise ValueError('GCM mode requires authentication tag')
            challenge_decrypted = cipher.decrypt_and_verify(challenge_encrypted, b64decode(datastore['tag']))
        else:
            cipher = AES.new(encryption_key, aes_mode, iv=initialization_vector)
            challenge_decrypted = cipher.decrypt(challenge_encrypted)
            challenge_decrypted = unpad(challenge_decrypted, AES.block_size)
        
        assert expected_challenge == challenge_decrypted, 'Challenge mismatch'
    except ValueError:
        sys.stderr.write('ERROR: Incorrect passphrase\n')
        sys.exit(1)
    except AssertionError as e:
        sys.stderr.write(f'ERROR: Challenge verification failed - {str(e)}\n')
        sys.exit(1)
    
    print('Datastore unlocked successfully!')
    
    displayTerminal(datastore, encryption_key, search_term)

def migrationMode(store_path: str):
    """
    Run password manager in migration mode.
    
    Migrates a CBC (legacy) datastore to GCM mode, creating a backup
    of the original file. Requires the passphrase to decrypt and verify.
    
    Args:
        store_path: Path to the datastore file to migrate
    """
    if not os.path.exists(store_path):
        sys.stderr.write(f"ERROR: Datastore not found at {store_path}\n")
        sys.exit(1)
    
    try:
        passphrase = getpass.getpass("Enter passphrase: ")
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)
    
    encryption_key = SHA256.new(data=passphrase.encode('utf-8')).digest()
    
    try:
        success = migrate_datastore_to_gcm(store_path, encryption_key, passphrase)
        if success:
            print('Migration completed successfully!')
        else:
            print('Migration skipped (datastore already in GCM mode)')
    except ValueError as e:
        sys.stderr.write(f'ERROR: {str(e)}\n')
        sys.exit(1)
    except IOError as e:
        sys.stderr.write(f'ERROR: {str(e)}\n')
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f'ERROR: Migration failed - {str(e)}\n')
        sys.exit(1)

def parseArgs():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Simple password manager with GUI and terminal modes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                    # Launch GUI with default datastore
  %(prog)s --no-gui           # Display passwords in terminal mode
  %(prog)s -s mystore.pws     # Use a different datastore file
  %(prog)s --no-gui --search github  # Search for entries containing "github"
  %(prog)s --migrate          # Migrate CBC datastore to GCM mode
        '''
    )
    parser.add_argument('-s', '--store', 
                       default='./data/store.pws',
                       help='Path to the password datastore (default: ./data/store.pws)')
    parser.add_argument('--no-gui', action='store_true',
                       help='Run in terminal mode (no GUI)')
    parser.add_argument('--search', type=str,
                       help='Search for entries containing this term (terminal mode only)')
    parser.add_argument('--migrate', action='store_true',
                       help='Migrate CBC (legacy) datastore to GCM mode (creates backup)')
    
    args = parser.parse_args(    )
    
    if not validate_store_path(args.store):
        sys.stderr.write(f"ERROR: Invalid or unsafe store path: {args.store}\n")
        sys.exit(1)
    
    return args

def main():
    'Main entry point'
    
    args = parseArgs()
    
    if args.migrate:
        migrationMode(args.store)
        return
    
    if args.no_gui:
        terminalMode(args.store, args.search)
        return
    
    root = tk.Tk()
    root.title('Simple password manager')
    root.minsize(width=800, height=600)
    
    style = ttk.Style()
    style.theme_use('clam')
    
    key = None
    uchall = None
    
    store_path = args.store
    data_dir = os.path.dirname(store_path) if os.path.dirname(store_path) else './data'
    
    if not os.path.exists(data_dir) or not os.path.exists(store_path):
        initdiag = InitialConfig(root, store_path)
        root.wait_window(initdiag.top)
        key = initdiag.key
        uchall = initdiag.challenge
    else:
        askkey = AskPassphrase(root)
        root.wait_window(askkey.top)
        key = askkey.key
        uchall = askkey.challenge
    try:
        assert key is not None, 'No key provided'
        assert len(key) == 32, 'Incorrect key length'
    except AssertionError as e:
        sys.stderr.write(f'Key error: {str(e)}\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    with open(store_path, 'r') as f:
        datastore = loads(f.read())
    
    was_migrated = migrate_legacy_datastore(datastore)
    if was_migrated:
        saveDatastore(datastore, store_path)
    
    iv = b64decode(datastore['iv'])
    cipher_mode = datastore['cipher_mode']
    aes_mode = get_aes_mode(cipher_mode)
    challenge = b64decode(datastore['challenge'])
    
    if cipher_mode == 'GCM':
        lcipher = AES.new(key, aes_mode, nonce=iv)
        if 'tag' not in datastore:
            sys.stderr.write('ERROR: GCM mode requires authentication tag\r\n')
            sys.exit()
        try:
            challenge = lcipher.decrypt_and_verify(challenge, b64decode(datastore['tag']))
        except ValueError as e:
            sys.stderr.write(f'ERROR: Authentication failed - {str(e)}\r\n')
            sys.exit()
    else:
        lcipher = AES.new(key, aes_mode, iv=iv)
        challenge = lcipher.decrypt(challenge)
        try:
            challenge = unpad(challenge, AES.block_size)
        except ValueError:
            sys.stderr.write('Incorrect passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')
            sys.exit()
    
    try:
        assert uchall == challenge, 'Challenge mismatch'
    except ValueError:
        sys.stderr.write('Incorrect passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    except AssertionError as e:
        sys.stderr.write(f'ERROR: Corrupted datastore\r\nChallenge error: {str(e)}\r\n\r\n')
        sys.exit()
    lcipher = None
    challenge = None
    uchall = None
    print('Datastore unlocked')
    root.attributes('-topmost', True)
    root.attributes('-topmost', False)
    root.protocol('WM_DELETE_WINDOW', lambda: saveAndExit(datastore, store_path))
    
    menu = tk.Menu(master=root)
    root.config(menu=menu)
    
    filemenu = tk.Menu(master=menu, tearoff=0)
    menu.add_cascade(label='File', menu=filemenu)
    filemenu.add_command(label='Save', command=lambda: saveDatastore(datastore, store_path))
    filemenu.add_command(label='Exit', command=lambda: saveAndExit(datastore, store_path))
    
    viewmenu = tk.Menu(master=menu, tearoff=0)
    menu.add_cascade(label='View', menu=viewmenu)
    
    def change_theme(theme_name):
        style.theme_use(theme_name)
        for i in range(viewmenu.index(tk.END) + 1):
            viewmenu.entryconfig(i, state='normal')
        print(f'Themed changed to: {theme_name}')
    
    available_themes = ['clam', 'alt', 'default', 'classic']
    for theme in available_themes:
        viewmenu.add_command(label=f"Theme: {theme}", 
                           command=lambda t=theme: change_theme(t))
    
    toolbar = tk.Frame(root)
    addbtn = ttk.Button(toolbar, text='Add', width=6)
    addbtn.pack(side=tk.LEFT, padx=2, pady=2)
    delbtn = ttk.Button(toolbar, text='Remove', width=6)
    delbtn.pack(side=tk.LEFT, padx=2, pady=2)
    edtbtn = ttk.Button(toolbar, text='Edit', width=6)
    edtbtn.pack(side=tk.LEFT, padx=2, pady=2)
    schlbl = ttk.Label(toolbar, text='Search:', width=8)
    schlbl.pack(side=tk.LEFT, padx=2, pady=2)
    schvar = tk.StringVar(master=toolbar)
    schety = ttk.Entry(master=toolbar, width=32, textvariable=schvar)
    schety.pack(side=tk.LEFT, padx=2)
    
    # Migration button - only show if datastore is in CBC mode
    migratebtn = None
    if cipher_mode == 'CBC':
        migratebtn = ttk.Button(toolbar, text='Migrate to GCM', width=15)
        migratebtn.pack(side=tk.LEFT, padx=2, pady=2)
    
    cubtn = ttk.Button(toolbar, text='Copy username', width=12)
    cubtn.pack(side=tk.RIGHT, padx=2, pady=2)
    cpbtn = ttk.Button(toolbar, text='Copy password', width=12)
    cpbtn.pack(side=tk.RIGHT, padx=2, pady=2)
    toolbar.pack(side=tk.TOP, fill=tk.X)
    
    listframe = tk.Frame(master=root)
    listsb = tk.Scrollbar(master=listframe, orient=tk.VERTICAL)
    listbox = ttk.Treeview(master=listframe, columns=['site', 'username', 'password'], show='headings', selectmode='browse')
    listbox.heading('site', text='Site')
    listbox.heading('username', text='Username')
    listbox.heading('password', text='Password')
    listsb.config(command=listbox.yview)
    cipher_mode = datastore['cipher_mode']
    aes_mode = get_aes_mode(cipher_mode)
    for k in datastore['store'].keys():
        entry = deepcopy(datastore['store'][k])
        
        if cipher_mode == 'GCM':
            entry_cipher = AES.new(key, aes_mode, nonce=b64decode(entry['iv']))
            if 'tag' not in entry:
                continue
            entry_data = entry_cipher.decrypt_and_verify(b64decode(entry['data']), b64decode(entry['tag']))
        else:
            entry_cipher = AES.new(key, aes_mode, iv=b64decode(entry['iv']))
            entry_data = entry_cipher.decrypt(b64decode(entry['data']))
            entry_data = unpad(entry_data, AES.block_size)
        
        entry_data = loads(entry_data.decode('utf-8'))
        listbox.insert('', tk.END, values=(deepcopy(k), deepcopy(entry_data['username']), deepcopy(entry_data['password'])))
    
    listsb.pack(side=tk.RIGHT, fill=tk.Y)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
    listframe.pack(fill=tk.BOTH, expand=1, padx=4, pady=4)
    
    migration_successful = False  # Track if migration succeeded
    
    def handle_migration():
        """Handle migration of datastore from CBC to GCM"""
        nonlocal migration_successful, datastore
        
        migrate_dialog = MigrateDialog(root)
        root.wait_window(migrate_dialog.top)
        
        if migrate_dialog.passphrase is None:
            return  # User cancelled
        
        try:
            migration_key = SHA256.new(data=migrate_dialog.passphrase.encode('utf-8')).digest()
            
            # Verify passphrase matches current key
            if migration_key != key:
                mbox.showerror('Migration Failed', 'Incorrect passphrase')
                return
            
            # Perform migration
            success = migrate_datastore_to_gcm(store_path, migration_key, migrate_dialog.passphrase)
            
            if success:
                # Reload the datastore from disk to get the migrated GCM version
                with open(store_path, 'r') as f:
                    datastore = loads(f.read())
                
                migration_successful = True
                mbox.showinfo('Migration Successful', 
                            'Datastore migrated to GCM mode successfully!\n'
                            'A backup has been created.\n\n'
                            'Please restart the application to continue.')
                root.quit()
            else:
                mbox.showinfo('Migration Skipped', 'Datastore is already in GCM mode')
        except Exception as e:
            mbox.showerror('Migration Failed', f'Migration failed: {str(e)}')
    
    addbtn.config(command=lambda: handlePw(root, datastore, key, listbox, PW_ADD))
    delbtn.config(command=lambda: handlePw(root, datastore, key, listbox, PW_DEL))
    edtbtn.config(command=lambda: handlePw(root, datastore, key, listbox, PW_EDT))
    cubtn.config(command=lambda: copyToClipboard(root, listbox, CB_USER))
    cpbtn.config(command=lambda: copyToClipboard(root, listbox, CB_PASS))
    
    if migratebtn is not None:
        migratebtn.config(command=handle_migration)
    
    schvar.trace('w', lambda unused_var, unused_idx, unused_mode, ds=datastore, encryption_key=key, lst=listbox, search_var=schvar: searchCallback(ds, encryption_key, lst, search_var))
    root.mainloop()
    # Only save if migration didn't happen (migration already saves the datastore)
    if not migration_successful:
        saveDatastore(datastore, store_path)

if __name__ == '__main__':
    main()
