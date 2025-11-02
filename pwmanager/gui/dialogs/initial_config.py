"""
Initial configuration dialog for password manager.

Dialog used when initializing a new datastore.
"""

import tkinter as tk

from pwmanager.crypto import derive_key, derive_challenge
from pwmanager.datastore import initialize_datastore


class InitialConfig:
    """
    Initial configuration dialog.
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
        passphrase_entry1 = self.passphrase_entry1 = tk.Entry(dialog_window, width=32, show="*")
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
        passphrase_entry2 = self.passphrase_entry2 = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry2.grid(
            row=2,
            column=1,
            sticky=tk.E
        )
        passphrase_entry2.bind('<Key>', self.verify)
        status_label = self.status_label = tk.Label(dialog_window, text='', fg='red')
        status_label.grid(
            row=3,
            column=0,
            columnspan=2
        )
        ok_button = self.ok_button = tk.Button(dialog_window, text="OK", command=self.ok, state=tk.DISABLED)
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
        passphrase1 = self.passphrase_entry1.get()
        passphrase2 = self.passphrase_entry2.get()
        
        if passphrase1 and passphrase2 and passphrase1 == passphrase2:
            self.ok_button.config(state=tk.NORMAL)
            self.status_label.config(text='')
        else:
            self.ok_button.config(state=tk.DISABLED)
            if passphrase1 and passphrase2 and len(passphrase1) == len(passphrase2):
                self.status_label.config(text='Passphrase does not match')
            else:
                self.status_label.config(text='')

    def ok(self):
        """
        Creates (if needed) the datastore and locks it with the given passphrase.
        """
        passphrase = self.passphrase_entry1.get()
        self.key = derive_key(passphrase)
        self.challenge = derive_challenge(passphrase)
        
        initialize_datastore(self.store_path, passphrase)
        
        self.top.grab_release()
        self.top.destroy()

