#!/usr/bin/env python3
# pylint: disable=line-too-long
"""
Simple password manager with support for multiple cryptographic modes.

This password manager stores website passwords encrypted with AES-256.
It supports two secure cipher modes:
- GCM (Galois/Counter Mode): Default for new datastores, provides authenticated encryption
- CBC (Cipher Block Chaining): Legacy mode, supported for backward compatibility

The encryption key is derived from a user passphrase using PBKDF2.
Each datastore includes cryptographic parameters (cipher and mode) for flexibility.
"""

import sys
import argparse
import os

from pwmanager.datastore import validate_store_path
from pwmanager.cli import terminal_mode, migration_mode
from pwmanager.gui.main_window import create_main_window


def parse_args():
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
    
    args = parser.parse_args()
    
    if not validate_store_path(args.store):
        sys.stderr.write(f"ERROR: Invalid or unsafe store path: {args.store}\n")
        sys.exit(1)
    
    return args


def main():
    """Main entry point"""
    
    args = parse_args()
    
    if args.migrate:
        migration_mode(args.store)
        return
    
    if args.no_gui:
        terminal_mode(args.store, args.search)
        return
    
    # GUI mode
    create_main_window(args.store)


if __name__ == '__main__':
    main()

