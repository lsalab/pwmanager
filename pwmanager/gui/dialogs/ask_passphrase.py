"""
Ask passphrase dialog for password manager.

Dialog used to unlock an existing datastore.
"""

import tkinter as tk
import tkinter.ttk as ttk

from pwmanager.gui.styles import (
    configure_dialog_styles, get_entry_style_config, StylingColors
)
from pwmanager.gui.rounded_button import RoundedButton


class AskPassphrase:
    """
    Dialog window used to unlock the datastore.
    """

    def __init__(self, parent):
        dialog_window = self.top = tk.Toplevel(parent)
        dialog_window.title('Unlock Password Manager')
        dialog_window.resizable(width=False, height=False)
        
        # Apply modern styling
        style = ttk.Style()
        configure_dialog_styles(dialog_window, style)
        entry_style = get_entry_style_config()
        
        # Override label font size for this dialog
        style.configure('Dialog.TLabel', font=('Segoe UI', 11))
        
        # Main frame
        main_frame = ttk.Frame(dialog_window, style='Dialog.TFrame', padding=30)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Enter passphrase:", style='Dialog.TLabel').grid(
            row=0, column=0, padx=5, pady=(0, 10), sticky=tk.W
        )
        passphrase_entry = self.passphrase_entry = tk.Entry(main_frame, width=35, show="*", **entry_style)
        passphrase_entry.grid(row=1, column=0, padx=5, pady=10, sticky=(tk.W, tk.E))
        ok_button = self.ok_button = RoundedButton(
            main_frame, 
            text="OK", 
            command=self.ok,
            bg_color=StylingColors.ACCENT.value,
            hover_color=StylingColors.HOVER.value,
            canvas_bg=StylingColors.BG.value,
            width=100
        )
        ok_button.grid(row=2, column=0, padx=5, pady=(10, 0))
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        dialog_window.columnconfigure(0, weight=1)
        dialog_window.rowconfigure(0, weight=1)
        
        self.__passphrase = None
        passphrase_entry.focus_set()
        passphrase_entry.bind('<Return>', self.ok)
        dialog_window.grab_set()
        dialog_window.attributes('-topmost', True)
        dialog_window.protocol('WM_DELETE_WINDOW', self.ok)

    @property
    def passphrase(self) -> str:
        return self.__passphrase

    def ok(self, event=None):  # pylint: disable=unused-argument
        if self.passphrase_entry.get():
            self.__passphrase = self.passphrase_entry.get()
            self.top.grab_release()
            self.top.destroy()

