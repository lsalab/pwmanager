"""
Command-line interface for password manager.

Handles terminal/CLI mode operations.
"""

import sys
import os
import getpass
from json import loads
from base64 import b64decode

from pwmanager.datastore import (
    load_datastore, save_datastore,
    decrypt_entry, verify_passphrase,
    get_encryption_key_from_datastore
)


def display_terminal(datastore: dict, encryption_key: bytes, search_term: str = None):
    """
    Display passwords in terminal mode.
    
    Decrypts all entries using GCM mode with authentication tags.
    
    Args:
        datastore: The datastore dictionary containing entries and cipher_mode
        encryption_key: The decryption key (PBKDF2-derived from passphrase)
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
    
    Loads and unlocks a datastore, then displays entries. Uses GCM cipher mode
    with PBKDF2 key derivation (100,000 iterations).
    
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
    
    try:
        datastore = load_datastore(store_path)
        
        if not verify_passphrase(datastore, passphrase):
            sys.stderr.write('ERROR: Incorrect passphrase\n')
            sys.exit(1)
        
        encryption_key = get_encryption_key_from_datastore(datastore, passphrase)
        
    except ValueError as e:
        sys.stderr.write(f'ERROR: {str(e)}\n')
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f'ERROR: {str(e)}\n')
        sys.exit(1)
    
    print('Datastore unlocked successfully!')
    
    display_terminal(datastore, encryption_key, search_term)

