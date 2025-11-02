"""
Command-line interface for password manager.

Handles terminal/CLI mode operations.
"""

import sys
import os
import getpass
from json import loads
from base64 import b64decode

from pwmanager.crypto import (
    derive_key, derive_challenge
)
from pwmanager.datastore import (
    load_datastore, save_datastore, migrate_legacy_datastore,
    decrypt_entry, migrate_datastore_to_gcm, verify_passphrase
)


def display_terminal(datastore: dict, encryption_key: bytes, search_term: str = None):
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
            entry_data = decrypt_entry(datastore['store'][site_name], encryption_key, cipher_mode)
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


def terminal_mode(store_path: str, search_term: str = None):
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
    
    encryption_key = derive_key(passphrase)
    expected_challenge = derive_challenge(passphrase)
    
    try:
        datastore = load_datastore(store_path)
        
        was_migrated = migrate_legacy_datastore(datastore)
        if was_migrated:
            save_datastore(datastore, store_path)
        
        if not verify_passphrase(datastore, encryption_key, expected_challenge):
            sys.stderr.write('ERROR: Incorrect passphrase\n')
            sys.exit(1)
        
    except ValueError as e:
        sys.stderr.write(f'ERROR: {str(e)}\n')
        sys.exit(1)
    except AssertionError as e:
        sys.stderr.write(f'ERROR: Challenge verification failed - {str(e)}\n')
        sys.exit(1)
    
    print('Datastore unlocked successfully!')
    
    display_terminal(datastore, encryption_key, search_term)


def migration_mode(store_path: str):
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
    
    encryption_key = derive_key(passphrase)
    
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

