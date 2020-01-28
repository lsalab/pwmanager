#!/usr/bin/env python3
'Simple password manager'

import os
import sys
import tkinter as tk
from json import dumps, loads
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class InitialConfig():

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
        ppstat = self.ppstat = tk.Label(top, text ='', fg='red')
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
        top.protocol('WM_DELETE_WINDOW', self.wmWinclose)

    def wmWinclose(self):
        pass
        self.ok()

    def verify(self, event):
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
        pp.grid(
            row=1,
            column=0,
            padx=2,
            pady=2
        )
        okbtn = self.okbtn = tk.Button(top, text="OK", command=self.ok)
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
    
    def ok(self):
        if len(self.pp.get()) > 0:
            self.key = SHA256.new(data=self.pp.get().encode('utf-8')).digest()
            self.challenge = ''
            for c in self.pp.get():
                self.challenge += chr(ord(c) ^ 0xff)
            self.challenge = SHA256.new(data=self.challenge.encode('utf-8')).digest()
            self.top.grab_release()
            self.top.destroy()

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
        assert len(key) == 32
        datastore = loads(open('./data/store.pws').read())
        iv = b64decode(datastore['iv'])
        lcipher = AES.new(key, AES.MODE_CBC, iv=iv)
        challenge = unpad(lcipher.decrypt(b64decode(datastore['challenge'])), AES.block_size)
        assert uchall == challenge
        lcipher = None
        challenge = None
        uchall = None
        sys.stderr.write('Datastore unlocked')
        # Menus
        menu = tk.Menu(master=root)
        root.config(menu=menu)
        filemenu = tk.Menu(master=menu)
        menu.add_cascade(label='File', menu=filemenu)
        filemenu.add_command(label='Exit', command=sys.exit)
        # Toolbar
        toolbar = tk.Frame(root)
        addbtn = tk.Button(toolbar, text='Add', width=6, command=lambda: print('TODO'))
        addbtn.pack(side=tk.LEFT, padx=2, pady=2)
        delbtn = tk.Button(toolbar, text='Remove', width=6, command=lambda: print('TODO'))
        delbtn.pack(side=tk.LEFT, padx=2, pady=2)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        # List box
        listframe = tk.Frame(master=root)
        listsb = tk.Scrollbar(master=listframe, orient=tk.VERTICAL)
        listbox = tk.Listbox(master=listframe, selectmode=tk.SINGLE, yscrollcommand=listsb.set)
        listsb.config(command=listbox.yview)
        for k in datastore['store'].keys():
            listbox.insert(tk.END, k)
        listsb.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
        listframe.pack(fill=tk.BOTH, expand=1, padx=4, pady=4)
        root.mainloop()
    except AssertionError:
        sys.stderr.write('Assertion error: Empty or incorrect passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')

if __name__ == '__main__':
    main()
