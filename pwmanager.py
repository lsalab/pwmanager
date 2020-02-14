#!/usr/bin/env python3
# pylint: disable=line-too-long,invalid-name
'Simple password manager'

import os
import sys
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as mbox
from json import dumps, loads
from base64 import b64encode, b64decode
from copy import deepcopy
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

PW_ADD = 0
PW_DEL = 1
PW_EDT = 2
CB_USER = 0
CB_PASS = 1

class InitialConfig():
    """
    Initial configuration dialog
    """

    def __init__(self, parent):
        top = self.top = tk.Toplevel(parent)
        top.wm_resizable(width=False, height=False)
        tk.Label(top, text='Datastore must be initialized and locked').grid(
            row=0,
            column=0,
            columnspan=2,
            padx=2,
            pady=2
        )
        tk.Label(top, text="Enter passphrase:").grid(
            row=1,
            column=0,
            padx=2,
            sticky=tk.W
        )
        pp1 = self.pp1 = tk.Entry(top, width=32, show="*")
        pp1.grid(
            row=1,
            column=1,
            sticky=tk.E
        )
        pp1.bind('<Key>', self.verify)
        tk.Label(top, text="Re-enter passphrase:").grid(
            row=2,
            column=0,
            padx=2,
            sticky=tk.W
        )
        pp2 = self.pp2 = tk.Entry(top, width=32, show="*")
        pp2.grid(
            row=2,
            column=1,
            sticky=tk.E
        )
        pp2.bind('<Key>', self.verify)
        ppstat = self.ppstat = tk.Label(top, text='', fg='red')
        ppstat.grid(
            row=3,
            column=0,
            columnspan=2
        )
        okbtn = self.okbtn = tk.Button(top, text="OK", command=self.ok, state=tk.DISABLED)
        okbtn.grid(
            row=4,
            column=0,
            columnspan=2,
            padx=2,
            pady=2
        )
        self.key = None
        self.challenge = None
        top.grab_set()
        top.wm_attributes('-topmost', True)
        top.protocol('WM_DELETE_WINDOW', self.ok)

    def verify(self, event):
        """
        Chacks whether both passphrases are the same
        """
        a = event.widget
        if a == self.pp1:
            b = self.pp2
        else:
            b = self.pp1
        if len(a.get()) >= 0 and a.get() + event.char == b.get():
            self.okbtn.config(state=tk.NORMAL)
            self.ppstat.config(text='')
            return True
        else:
            self.okbtn.config(state=tk.DISABLED)
            self.ppstat.config(text='Passphrase does not match')
            return False

    def ok(self):
        """
        Creates (if needed) the datastore and locks it with the given passphrase

        Encryption key is the SHA256 digest of passphrase, as bytes

        A challenge generated as the SHA256 digest of the ones complement of the passphrase.
        The challenge is encrypted using AES-256 in CBC mode with a random 128-bit IV and the key.

        Challenge = AES256(IV, Key, SHA256(CONCAT(i XOR 0xFF for i in passphrase)))
        """
        config = {}
        config['store'] = {}
        passphrase = self.pp1.get()
        self.key = SHA256.new(data=passphrase.encode('utf-8')).digest()
        challenge = ''
        for c in passphrase:
            challenge += chr(ord(c) ^ 0xff)
        self.challenge = SHA256.new(data=challenge.encode('utf-8')).digest()
        iv = get_random_bytes(16)
        config['iv'] = b64encode(iv).decode('utf-8')
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        config['challenge'] = b64encode(cipher.encrypt(pad(self.challenge, AES.block_size))).decode('utf-8')
        if not os.path.exists('./data'):
            os.mkdir('./data')
        with open('./data/store.pws', 'w') as cfile:
            cfile.write(dumps(config, indent=2))
        self.top.grab_release()
        self.top.destroy()

class AskPassphrase():
    """
    Dialog window used to unlock the datastore.
    """

    def __init__(self, parent):
        top = self.top = tk.Toplevel(parent)
        top.wm_resizable(width=False, height=False)
        tk.Label(top, text="Enter passphrase:").grid(
            row=0,
            column=0,
            padx=2,
            pady=2
        )
        pp = self.pp = tk.Entry(top, width=32, show="*")
        pp.grid(row=1, column=0, padx=2, pady=2)
        okbtn = self.okbtn = tk.Button(top, text="OK", command=self.ok)
        okbtn.grid(row=4, column=0, columnspan=2, padx=2, pady=2)
        self.__key = None
        self.__challenge = None
        pp.focus_set()
        pp.bind('<Return>', self.ok)
        top.grab_set()
        top.wm_attributes('-topmost', True)
        top.protocol('WM_DELETE_WINDOW', self.ok)

    @property
    def key(self) -> bytes:
        return bytes(self.__key)

    @key.setter
    def key(self, value: bytes):
        if value is not None and isinstance(value, bytes):
            self.__key = value

    @property
    def challenge(self) -> bytes:
        return bytes(self.__challenge)

    @challenge.setter
    def challenge(self, value: bytes):
        if value is not None and isinstance(value, bytes):
            self.__challenge = value

    def ok(self, event=None): # pylint: disable=unused-argument
        if self.pp.get():
            self.__key = SHA256.new(data=self.pp.get().encode('utf-8')).digest()
            self.__challenge = ''
            for c in self.pp.get():
                self.__challenge += chr(ord(c) ^ 0xff)
            self.__challenge = SHA256.new(data=self.__challenge.encode('utf-8')).digest()
            self.top.grab_release()
            self.top.destroy()

class PWDiag(): # pylint: disable=too-many-instance-attributes
    """Password information dialog"""

    def __init__(self, parent, **kwargs):
        top = self.top = tk.Toplevel(master=parent)
        self.__site = tk.StringVar(master=top)
        self.__username = tk.StringVar(master=top)
        self.__password = tk.StringVar(master=top)
        tk.Label(master=top, text='Site:').grid(
            row=0, column=0,
            padx=2, pady=2
        )
        se = self.se = tk.Entry(master=top, width=32, textvariable=self.__site)
        se.grid(row=0, column=1, columnspan=2, padx=2, pady=2)
        se.bind('<Return>', self.ok)
        tk.Label(master=top, text='Username:').grid(
            row=1, column=0,
            padx=2, pady=2
        )
        ue = self.ue = tk.Entry(master=top, width=32, textvariable=self.__username)
        ue.grid(row=1, column=1, columnspan=2, padx=2, pady=2)
        ue.bind('<Return>', self.ok)
        tk.Label(master=top, text='Password:').grid(
            row=2, column=0,
            padx=2, pady=2
        )
        pe = self.pe = tk.Entry(master=top, width=32, textvariable=self.__password)
        pe.grid(row=2, column=1, columnspan=2, padx=2, pady=2)
        pe.bind('<Return>', self.ok)
        pe.bind('<FocusIn>', lambda evt: self.pe.config(show=''))
        pe.bind('<FocusOut>', lambda evt: self.pe.config(show='*'))
        okbtn = self.okbtn = tk.Button(top, text="OK", command=self.ok)
        okbtn.grid(row=3, column=0, columnspan=2, padx=2, pady=2)
        if 'site' in kwargs:
            self.__site.set(kwargs['site'])
        if 'username' in kwargs:
            self.__username.set(kwargs['username'])
        if 'password' in kwargs:
            self.__password.set(kwargs['password'])
        top.grab_set()
        top.wm_attributes('-topmost', True)
        se.focus_set()
        top.protocol('WM_DELETE_WINDOW', self.ok)

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

    def ok(self, event=None): # pylint: disable=unused-argument
        self.top.grab_release()
        self.top.destroy()

def handlePw(master: tk.Tk, datastore: dict, key: bytes, guilist: ttk.Treeview, action: int):
    if action in [PW_ADD, PW_EDT]:
        pwd = None
        if action == PW_ADD:
            pwd = PWDiag(master)
        else:
            if guilist.focus() is '':
                return
            itemid = guilist.selection()[0]
            sel_item = guilist.item(itemid)
            sel_item = sel_item['values']
            osite = sel_item[0]
            ouser = sel_item[1]
            opass = sel_item[2]
            pwd = PWDiag(master, site=deepcopy(osite), username=deepcopy(ouser), password=deepcopy(opass))
            pwd.se.config(state=tk.DISABLED)
            pwd.ue.config(state=tk.DISABLED)
            pwd.pe.focus_set()
            guilist.delete(itemid)
            del osite
            del ouser
            del opass
            del sel_item
        master.wait_window(pwd.top)
        datastore.pop(pwd.site, None)
        entry = {}
        entry_iv = get_random_bytes(16)
        entry_cipher = AES.new(key, AES.MODE_CBC, iv=entry_iv)
        entry['iv'] = b64encode(entry_iv).decode('utf-8')
        entry_data = {}
        entry_data['username'] = pwd.username
        entry_data['password'] = pwd.password
        entry_data = dumps(entry_data).encode('utf-8')
        entry_data = entry_cipher.encrypt(pad(entry_data, AES.block_size))
        entry['data'] = b64encode(entry_data).decode('utf-8')
        datastore['store'][pwd.site] = deepcopy(entry)
        guilist.insert('', tk.END, values=(deepcopy(pwd.site), deepcopy(pwd.username), deepcopy(pwd.password)))
    elif action == PW_DEL:
        if guilist.focus() is '':
            return
        itemid = guilist.selection()[0]
        site = guilist.item(itemid)['values'][0]
        if mbox.askyesno(title='Delete password', message='Are you sure you want to delete the selected password?\r\n(This cannot be undone)'):
            datastore['store'].pop(site, None)
            guilist.delete(itemid)
    else:
        print('ERROR: Unknown action')

def saveDatastore(datastore: dict):
    with open('./data/store.pws', 'w') as cfile:
        cfile.write(dumps(datastore, indent=2))
        cfile.flush()
        print('Datastore saved!')

def saveAndExit(datastore: dict):
    saveDatastore(datastore)
    sys.exit(0)

def copyToClipboard(master: tk.Tk, listbox: ttk.Treeview, val: int):
    if listbox.focus() == '':
        return
    itemid = listbox.selection()[0]
    values = listbox.item(itemid)['values']
    master.clipboard_clear()
    if val == CB_USER:
        master.clipboard_append(values[1])
    elif val == CB_PASS:
        master.clipboard_append(values[2])
    else:
        print('Unknown header')
    master.update()

def main():
    'Main entry point'

    root = tk.Tk()
    root.wm_title(string='Simple password manager')
    root.wm_minsize(width=800, height=600)
    # Check data directory and/or unlock datastore
    key = None
    uchall = None
    if not os.path.exists('./data') or not os.path.exists('./data/store.pws'):
        initdiag = InitialConfig(root)
        root.wait_window(initdiag.top)
        key = initdiag.key
        uchall = initdiag.challenge
    else:
        askkey = AskPassphrase(root)
        root.wait_window(askkey.top)
        key = askkey.key
        uchall = askkey.challenge
    try:
        assert key is not None
        assert len(key) == 32
    except AssertionError:
        sys.stderr.write('Empty passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    datastore = loads(open('./data/store.pws').read())
    iv = b64decode(datastore['iv'])
    lcipher = AES.new(key, AES.MODE_CBC, iv=iv)
    challenge = b64decode(datastore['challenge'])
    challenge = lcipher.decrypt(challenge)
    try:
        challenge = unpad(challenge, AES.block_size)
        assert uchall == challenge
    except ValueError:
        sys.stderr.write('Incorrect passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    except AssertionError:
        sys.stderr.write('ERROR: Corrupted datastore\r\n\r\n')
        sys.exit()
    lcipher = None
    challenge = None
    uchall = None
    print('Datastore unlocked')
    root.wm_attributes('-topmost', True)
    root.wm_attributes('-topmost', False)
    root.protocol('WM_DELETE_WINDOW', lambda: saveAndExit(datastore))
    # Menus
    menu = tk.Menu(master=root)
    root.config(menu=menu)
    filemenu = tk.Menu(master=menu, tearoff=0)
    menu.add_cascade(label='File', menu=filemenu)
    filemenu.add_command(label='Save', command=lambda: saveDatastore(datastore))
    filemenu.add_command(label='Exit', command=lambda: saveAndExit(datastore))
    # Toolbar
    toolbar = tk.Frame(root)
    addbtn = tk.Button(toolbar, text='Add', width=6)
    addbtn.pack(side=tk.LEFT, padx=2, pady=2)
    delbtn = tk.Button(toolbar, text='Remove', width=6)
    delbtn.pack(side=tk.LEFT, padx=2, pady=2)
    edtbtn = tk.Button(toolbar, text='Edit', width=6)
    edtbtn.pack(side=tk.LEFT, padx=2, pady=2)
    cubtn = tk.Button(toolbar, text='Copy username', width=12)
    cubtn.pack(side=tk.RIGHT, padx=2, pady=2)
    cpbtn = tk.Button(toolbar, text='Copy password', width=12)
    cpbtn.pack(side=tk.RIGHT, padx=2, pady=2)
    toolbar.pack(side=tk.TOP, fill=tk.X)
    # List box
    listframe = tk.Frame(master=root)
    listsb = tk.Scrollbar(master=listframe, orient=tk.VERTICAL)
    listbox = ttk.Treeview(master=listframe, columns=['site', 'username', 'password'], show='headings', selectmode='browse')
    listbox.heading('site', text='Site')
    listbox.heading('username', text='Username')
    listbox.heading('password', text='Password')
    listsb.config(command=listbox.yview)
    for k in datastore['store'].keys():
        entry = deepcopy(datastore['store'][k])
        entry_cipher = AES.new(key, AES.MODE_CBC, iv=b64decode(entry['iv']))
        entry_data = entry_cipher.decrypt(b64decode(entry['data']))
        entry_data = unpad(entry_data, AES.block_size)
        entry_data = loads(entry_data.decode('utf-8'))
        listbox.insert('', tk.END, values=(deepcopy(k), deepcopy(entry_data['username']), deepcopy(entry_data['password'])))
    #     listbox.insert('', 'end', k['values'])
    # listbox.insert('', tk.END, values=('test', 'test', 'test'))
    listsb.pack(side=tk.RIGHT, fill=tk.Y)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
    listframe.pack(fill=tk.BOTH, expand=1, padx=4, pady=4)
    # Button configs
    addbtn.config(command=lambda: handlePw(root, datastore, key, listbox, PW_ADD))
    delbtn.config(command=lambda: handlePw(root, datastore, key, listbox, PW_DEL))
    edtbtn.config(command=lambda: handlePw(root, datastore, key, listbox, PW_EDT))
    cubtn.config(command=lambda: copyToClipboard(root, listbox, CB_USER))
    cpbtn.config(command=lambda: copyToClipboard(root, listbox, CB_PASS))
    root.mainloop()
    saveDatastore(datastore)

if __name__ == '__main__':
    main()
