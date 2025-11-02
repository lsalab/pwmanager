"""
Ask passphrase dialog for password manager.

Dialog used to unlock an existing datastore.
"""

import tkinter as tk

from pwmanager.crypto import derive_key, derive_challenge


class AskPassphrase:
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
        passphrase_entry = self.passphrase_entry = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry.grid(row=1, column=0, padx=2, pady=2)
        ok_button = self.ok_button = tk.Button(dialog_window, text="OK", command=self.ok)
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

    def ok(self, event=None):  # pylint: disable=unused-argument
        if self.passphrase_entry.get():
            passphrase = self.passphrase_entry.get()
            self.__key = derive_key(passphrase)
            self.__challenge = derive_challenge(passphrase)
            self.top.grab_release()
            self.top.destroy()

