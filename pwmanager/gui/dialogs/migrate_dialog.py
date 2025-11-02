"""
Migration dialog for password manager.

Dialog used to migrate a CBC datastore to GCM mode.
"""

import tkinter as tk


class MigrateDialog:
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
        passphrase_entry = self.passphrase_entry = tk.Entry(dialog_window, width=32, show="*")
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

    def ok(self, event=None):  # pylint: disable=unused-argument
        if self.passphrase_entry.get():
            self.passphrase = self.passphrase_entry.get()
            self.top.grab_release()
            self.top.destroy()
        else:
            self.status_label.config(text='Please enter passphrase', fg='red')

    def cancel(self):
        self.passphrase = None
        self.top.grab_release()
        self.top.destroy()

