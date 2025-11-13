"""
Password information dialog for password manager.

Dialog used to add or edit password entries.
"""

import tkinter as tk
import tkinter.ttk as ttk

from pwmanager.crypto import generate_random_password
from pwmanager.gui.styles import (
    configure_dialog_styles, StylingColors
)
from pwmanager.gui.rounded_button import RoundedButton


class PasswordDialog:  # pylint: disable=too-many-instance-attributes
    """Password information dialog"""

    def __init__(self, parent, **kwargs):
        dialog_window = self.top = tk.Toplevel(master=parent)
        dialog_window.title('Password Entry')
        dialog_window.resizable(width=False, height=False)
        
        # Apply modern styling
        style = ttk.Style()
        configure_dialog_styles(dialog_window, style)
        
        # Main frame
        main_frame = ttk.Frame(dialog_window, style='Dialog.TFrame', padding=20)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.__site = tk.StringVar(master=dialog_window)
        self.__username = tk.StringVar(master=dialog_window)
        self.__password = tk.StringVar(master=dialog_window)
        self.__ok_pressed = False
        
        # Site field
        ttk.Label(main_frame, text='Site:', style='Dialog.TLabel').grid(
            row=0, column=0, padx=5, pady=8, sticky=tk.W
        )
        site_entry = self.site_entry = ttk.Entry(main_frame, width=35, textvariable=self.__site, style='Dialog.TEntry')
        site_entry.grid(row=0, column=1, padx=5, pady=8, sticky=(tk.W, tk.E))
        site_entry.bind('<Return>', self.ok)
        
        # Username field
        ttk.Label(main_frame, text='Username:', style='Dialog.TLabel').grid(
            row=1, column=0, padx=5, pady=8, sticky=tk.W
        )
        username_entry = self.username_entry = ttk.Entry(main_frame, width=35, textvariable=self.__username, style='Dialog.TEntry')
        username_entry.grid(row=1, column=1, padx=5, pady=8, sticky=(tk.W, tk.E))
        username_entry.bind('<Return>', self.ok)
        
        # Password field
        ttk.Label(main_frame, text='Password:', style='Dialog.TLabel').grid(
            row=2, column=0, padx=5, pady=8, sticky=tk.W
        )
        password_entry = self.password_entry = ttk.Entry(main_frame, width=35, textvariable=self.__password, 
                                                          style='Dialog.TEntry', show='*')
        password_entry.grid(row=2, column=1, padx=5, pady=8, sticky=(tk.W, tk.E))
        password_entry.bind('<Return>', self.ok)
        password_entry.bind('<FocusIn>', lambda evt: self.password_entry.config(show=''))
        password_entry.bind('<FocusOut>', lambda evt: self.password_entry.config(show='*'))
        
        # Button frame
        button_frame = ttk.Frame(main_frame, style='Dialog.TFrame')
        button_frame.grid(row=3, column=0, columnspan=2, pady=15, sticky=tk.E)
        
        generate_button = self.generate_button = RoundedButton(
            button_frame, 
            text="Generate", 
            command=self.__generate,
            bg_color=StylingColors.ACCENT.value,
            hover_color=StylingColors.HOVER.value,
            canvas_bg=StylingColors.BG.value
        )
        generate_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ok_button = self.ok_button = RoundedButton(
            button_frame, 
            text="OK", 
            command=self.ok,
            bg_color=StylingColors.ACCENT.value,
            hover_color=StylingColors.HOVER.value,
            canvas_bg=StylingColors.BG.value
        )
        ok_button.pack(side=tk.LEFT, padx=0)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        dialog_window.columnconfigure(0, weight=1)
        dialog_window.rowconfigure(0, weight=1)
        
        if 'site' in kwargs:
            self.__site.set(kwargs['site'])
        if 'username' in kwargs:
            self.__username.set(kwargs['username'])
        if 'password' in kwargs:
            self.__password.set(kwargs['password'])
        dialog_window.grab_set()
        dialog_window.attributes('-topmost', True)
        site_entry.focus_set()
        dialog_window.protocol('WM_DELETE_WINDOW', self.__done)

    @property
    def site(self) -> str:
        return str(self.__site.get())

    @site.setter
    def site(self, value: str):
        if value is not None and isinstance(value, str):
            self.__site.set(value)
        else:
            self.__site.set('')

    @property
    def username(self) -> str:
        return str(self.__username.get())

    @username.setter
    def username(self, value: str):
        if value is not None and isinstance(value, str):
            self.__username.set(value)
        else:
            self.__username.set('')

    @property
    def password(self) -> str:
        return str(self.__password.get())

    @password.setter
    def password(self, value: str):
        if value is not None and isinstance(value, str):
            self.__password.set(value)
        else:
            self.__password.set('')

    @property
    def ok_pressed(self) -> bool:
        return self.__ok_pressed
    
    @ok_pressed.setter
    def ok_pressed(self, value: bool=False):
        self.__ok_pressed = value

    def __done(self, event=None):
        self.top.grab_release()
        self.top.destroy()

    def __generate(self):
        self.password = generate_random_password()

    def ok(self, event=None):  # pylint: disable=unused-argument
        self.__ok_pressed = True
        self.__done()

