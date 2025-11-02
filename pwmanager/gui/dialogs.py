"""
GUI dialog windows for password manager.

This module provides backward compatibility. All dialogs have been moved
to the dialogs subfolder.

For new code, import from the dialogs package:
    from pwmanager.gui.dialogs import InitialConfig, AskPassphrase, PasswordDialog

Or import from the gui package:
    from pwmanager.gui import InitialConfig, AskPassphrase, PasswordDialog
"""

# Re-export for backward compatibility
from pwmanager.gui.dialogs import (
    InitialConfig,
    AskPassphrase,
    PasswordDialog
)

__all__ = ['InitialConfig', 'AskPassphrase', 'PasswordDialog']
