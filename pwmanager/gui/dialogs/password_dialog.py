"""
Password information dialog for password manager.

Dialog used to add or edit password entries.
"""

import tkinter as tk

from pwmanager.crypto import generate_random_password


class PasswordDialog:  # pylint: disable=too-many-instance-attributes
    """Password information dialog"""

    def __init__(self, parent, **kwargs):
        dialog_window = self.top = tk.Toplevel(master=parent)
        self.__site = tk.StringVar(master=dialog_window)
        self.__username = tk.StringVar(master=dialog_window)
        self.__password = tk.StringVar(master=dialog_window)
        self.__ok_pressed = False
        tk.Label(master=dialog_window, text='Site:').grid(
            row=0, column=0,
            padx=2, pady=2
        )
        site_entry = self.site_entry = tk.Entry(master=dialog_window, width=32, textvariable=self.__site)
        site_entry.grid(row=0, column=1, columnspan=2, padx=2, pady=2)
        site_entry.bind('<Return>', self.ok)
        tk.Label(master=dialog_window, text='Username:').grid(
            row=1, column=0,
            padx=2, pady=2
        )
        username_entry = self.username_entry = tk.Entry(master=dialog_window, width=32, textvariable=self.__username)
        username_entry.grid(row=1, column=1, columnspan=2, padx=2, pady=2)
        username_entry.bind('<Return>', self.ok)
        tk.Label(master=dialog_window, text='Password:').grid(
            row=2, column=0,
            padx=2, pady=2
        )
        password_entry = self.password_entry = tk.Entry(master=dialog_window, width=32, textvariable=self.__password)
        password_entry.grid(row=2, column=1, columnspan=2, padx=2, pady=2)
        password_entry.bind('<Return>', self.ok)
        password_entry.bind('<FocusIn>', lambda evt: self.password_entry.config(show=''))
        password_entry.bind('<FocusOut>', lambda evt: self.password_entry.config(show='*'))
        ok_button = self.ok_button = tk.Button(dialog_window, text="OK", command=self.ok)
        ok_button.grid(row=3, column=2, columnspan=1, padx=10, pady=2, sticky='ew')
        generate_button = self.generate_button = tk.Button(dialog_window, text="Generate", command=self.__generate)
        generate_button.grid(row=3, column=1, columnspan=1, padx=2, pady=2, sticky='ew')
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

