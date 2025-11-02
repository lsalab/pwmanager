"""
Dialog windows for password manager.

This package contains all GUI dialog classes.
"""

from pwmanager.gui.dialogs.initial_config import InitialConfig
from pwmanager.gui.dialogs.ask_passphrase import AskPassphrase
from pwmanager.gui.dialogs.migrate_dialog import MigrateDialog
from pwmanager.gui.dialogs.password_dialog import PasswordDialog

__all__ = ['InitialConfig', 'AskPassphrase', 'MigrateDialog', 'PasswordDialog']

