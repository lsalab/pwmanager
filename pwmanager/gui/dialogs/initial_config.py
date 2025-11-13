"""
Initial configuration dialog for password manager.

Dialog used when initializing a new datastore.
"""

import tkinter as tk
import tkinter.ttk as ttk

from pwmanager.datastore import initialize_datastore
from pwmanager.gui.styles import (
    configure_dialog_styles, get_entry_style_config, StylingColors
)
from pwmanager.gui.rounded_button import RoundedButton


class InitialConfig:
    """
    Initial configuration dialog.
    """

    def __init__(self, parent, store_path=None):
        self.store_path = store_path if store_path else './data/store.pws'
        dialog_window = self.top = tk.Toplevel(parent)
        dialog_window.title('Initialize Password Manager')
        dialog_window.resizable(width=False, height=False)
        
        # Apply modern styling
        style = ttk.Style()
        configure_dialog_styles(dialog_window, style)
        entry_style = get_entry_style_config()
        
        # Main frame
        main_frame = ttk.Frame(dialog_window, style='Dialog.TFrame', padding=30)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text='Datastore must be initialized and locked', 
                  style='Dialog.TLabel', font=('Segoe UI', 11, 'bold')).grid(
            row=0, column=0, columnspan=2, padx=5, pady=(0, 20), sticky=tk.W
        )
        ttk.Label(main_frame, text="Enter passphrase:", style='Dialog.TLabel').grid(
            row=1, column=0, padx=5, pady=8, sticky=tk.W
        )
        passphrase_entry1 = self.passphrase_entry1 = tk.Entry(main_frame, width=35, show="*", **entry_style)
        passphrase_entry1.grid(row=1, column=1, padx=5, pady=8, sticky=(tk.W, tk.E))
        passphrase_entry1.bind('<Key>', self.verify)
        ttk.Label(main_frame, text="Re-enter passphrase:", style='Dialog.TLabel').grid(
            row=2, column=0, padx=5, pady=8, sticky=tk.W
        )
        passphrase_entry2 = self.passphrase_entry2 = tk.Entry(main_frame, width=35, show="*", **entry_style)
        passphrase_entry2.grid(row=2, column=1, padx=5, pady=8, sticky=(tk.W, tk.E))
        passphrase_entry2.bind('<Key>', self.verify)
        status_label = self.status_label = tk.Label(main_frame, text='', fg=StylingColors.ERROR.value, 
                                                     bg=StylingColors.BG.value, font=('Segoe UI', 9))
        status_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        ok_button = self.ok_button = RoundedButton(
            main_frame, 
            text="OK", 
            command=self.ok,
            bg_color=StylingColors.ACCENT.value,
            hover_color=StylingColors.HOVER.value,
            canvas_bg=StylingColors.BG.value,
            state='disabled',
            width=120
        )
        ok_button.grid(row=4, column=0, columnspan=2, padx=5, pady=(15, 0))
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        dialog_window.columnconfigure(0, weight=1)
        dialog_window.rowconfigure(0, weight=1)
        
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
        initialize_datastore(self.store_path, passphrase)
        
        self.top.grab_release()
        self.top.destroy()

