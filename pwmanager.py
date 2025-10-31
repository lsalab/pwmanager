#!/usr/bin/env python3
# pylint: disable=line-too-long
'Simple password manager'

import os
import sys
import argparse
import getpass
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as mbox
from json import dumps, loads
from base64 import b64encode, b64decode
from copy import deepcopy
# Try importing from Crypto (pycryptodome standard package)
# Fall back to Cryptodome (pycryptodomex or older installations)
try:
    from Crypto.Hash import SHA256
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except (ImportError, ModuleNotFoundError):
    try:
        from Cryptodome.Hash import SHA256
        from Cryptodome.Cipher import AES
        from Cryptodome.Random import get_random_bytes
        from Cryptodome.Util.Padding import pad, unpad
    except ImportError as e:
        sys.stderr.write(
            "ERROR: Could not import cryptographic libraries.\n"
            "Please install PyCryptodome or PyCryptodomex:\n"
            "  pip install pycryptodome\n"
            "  # or\n"
            "  pip install pycryptodomex\n\n"
        )
        sys.exit(1)

PW_ADD = 0
PW_DEL = 1
PW_EDT = 2
CB_USER = 0
CB_PASS = 1

# Constants
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32
PASSWORD_LENGTH = 24

def validate_store_path(path: str) -> bool:
    """
    Validate that the store path is safe to use.
    Prevents directory traversal and other path-based attacks.
    """
    if not path:
        return False
    
    # Check for dangerous patterns
    dangerous_patterns = ['..', '/etc', '/proc', '/sys', '/dev']
    path_lower = path.lower()
    
    for pattern in dangerous_patterns:
        if pattern in path_lower:
            return False
    
    # Ensure it doesn't start with / to prevent absolute path access
    # (unless explicitly in current directory structure)
    if path.startswith('/') and not path.startswith('./'):
        return False
    
    return True

class InitialConfig():
    """
    Initial configuration dialog
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
        passphrase_entry1 = self.pp1 = tk.Entry(dialog_window, width=32, show="*")
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
        passphrase_entry2 = self.pp2 = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry2.grid(
            row=2,
            column=1,
            sticky=tk.E
        )
        passphrase_entry2.bind('<Key>', self.verify)
        status_label = self.ppstat = tk.Label(dialog_window, text='', fg='red')
        status_label.grid(
            row=3,
            column=0,
            columnspan=2
        )
        ok_button = self.okbtn = tk.Button(dialog_window, text="OK", command=self.ok, state=tk.DISABLED)
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
        passphrase1 = self.pp1.get()
        passphrase2 = self.pp2.get()
        
        # Only enable OK if both fields have content and match
        if passphrase1 and passphrase2 and passphrase1 == passphrase2:
            self.okbtn.config(state=tk.NORMAL)
            self.ppstat.config(text='')
        else:
            self.okbtn.config(state=tk.DISABLED)
            if passphrase1 and passphrase2 and len(passphrase1) == len(passphrase2):
                self.ppstat.config(text='Passphrase does not match')
            else:
                self.ppstat.config(text='')

    def ok(self):
        """
        Creates (if needed) the datastore and locks it with the given passphrase

        Encryption key is the SHA256 digest of passphrase, as bytes

        A challenge generated as the SHA256 digest of the ones complement of the passphrase.
        The challenge is encrypted using AES-256 in CBC mode with a random 128-bit IV and the key.

        Challenge = AES256(IV, Key, SHA256(CONCAT(i XOR 0xFF for i in passphrase)))
        """
        config_data = {}
        config_data['store'] = {}
        passphrase = self.pp1.get()
        self.key = SHA256.new(data=passphrase.encode('utf-8')).digest()
        challenge_string = ''
        for char in passphrase:
            challenge_string += chr(ord(char) ^ 0xff)
        self.challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
        initialization_vector = get_random_bytes(AES_BLOCK_SIZE)
        config_data['iv'] = b64encode(initialization_vector).decode('utf-8')
        cipher = AES.new(self.key, AES.MODE_CBC, iv=initialization_vector)
        config_data['challenge'] = b64encode(cipher.encrypt(pad(self.challenge, AES.block_size))).decode('utf-8')
        
        # Create data directory if needed
        data_dir = os.path.dirname(self.store_path)
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        with open(self.store_path, 'w') as config_file:
            config_file.write(dumps(config_data, indent=2))
        self.top.grab_release()
        self.top.destroy()

class AskPassphrase():
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
        passphrase_entry = self.pp = tk.Entry(dialog_window, width=32, show="*")
        passphrase_entry.grid(row=1, column=0, padx=2, pady=2)
        ok_button = self.okbtn = tk.Button(dialog_window, text="OK", command=self.ok)
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

    def ok(self, event=None): # pylint: disable=unused-argument
        if self.pp.get():
            passphrase = self.pp.get()
            self.__key = SHA256.new(data=passphrase.encode('utf-8')).digest()
            challenge_string = ''
            for char in passphrase:
                challenge_string += chr(ord(char) ^ 0xff)
            self.__challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
            self.top.grab_release()
            self.top.destroy()

class PWDiag(): # pylint: disable=too-many-instance-attributes
    """Password information dialog"""

    def __init__(self, parent, **kwargs):
        top = self.top = tk.Toplevel(master=parent)
        self.__site = tk.StringVar(master=top)
        self.__username = tk.StringVar(master=top)
        self.__password = tk.StringVar(master=top)
        self.__okpressed = False
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
        okbtn.grid(row=3, column=2, columnspan=1, padx=10, pady=2, sticky='ew')
        genbtn = self.genbtn = tk.Button(top, text="Generate", command=self.__generate)
        genbtn.grid(row=3, column=1, columnspan=1, padx=2, pady=2, sticky='ew')
        if 'site' in kwargs:
            self.__site.set(kwargs['site'])
        if 'username' in kwargs:
            self.__username.set(kwargs['username'])
        if 'password' in kwargs:
            self.__password.set(kwargs['password'])
        top.grab_set()
        top.attributes('-topmost', True)
        se.focus_set()
        top.protocol('WM_DELETE_WINDOW', self.__done)

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
    def okpressed(self) -> bool:
        return self.__okpressed
    
    @okpressed.setter
    def okpressed(self, value: bool=False):
        self.__okpressed = value

    def __done(self, event=None):
        self.top.grab_release()
        self.top.destroy()

    def __generate(self):
        self.password = b64encode(get_random_bytes(PASSWORD_LENGTH)).decode('utf-8')

    def ok(self, event=None): # pylint: disable=unused-argument
        self.__okpressed = True
        self.__done()

def handlePw(master: tk.Tk, datastore: dict, key: bytes, guilist: ttk.Treeview, action: int):
    if action in [PW_ADD, PW_EDT]:
        password_dialog = None
        if action == PW_ADD:
            password_dialog = PWDiag(master)
        else:
            if guilist.focus() == '':
                return
            selected_item_id = guilist.selection()[0]
            selected_item = guilist.item(selected_item_id)
            selected_values = selected_item['values']
            old_site = selected_values[0]
            old_username = selected_values[1]
            old_password = selected_values[2]
            password_dialog = PWDiag(master, site=deepcopy(old_site), username=deepcopy(old_username), password=deepcopy(old_password))
            password_dialog.se.config(state=tk.DISABLED)
            password_dialog.ue.config(state=tk.DISABLED)
            password_dialog.pe.focus_set()
            guilist.delete(selected_item_id)
            del old_site
            del old_username
            del old_password
            del selected_values
        master.wait_window(password_dialog.top)
        if password_dialog.okpressed and password_dialog.site.strip() != '':
            datastore.pop(password_dialog.site, None)
            entry = {}
            entry_initialization_vector = get_random_bytes(AES_BLOCK_SIZE)
            entry_cipher = AES.new(key, AES.MODE_CBC, iv=entry_initialization_vector)
            entry['iv'] = b64encode(entry_initialization_vector).decode('utf-8')
            entry_data = {}
            entry_data['username'] = password_dialog.username
            entry_data['password'] = password_dialog.password
            entry_data_json = dumps(entry_data).encode('utf-8')
            entry_data_encrypted = entry_cipher.encrypt(pad(entry_data_json, AES.block_size))
            entry['data'] = b64encode(entry_data_encrypted).decode('utf-8')
            datastore['store'][password_dialog.site] = deepcopy(entry)
            guilist.insert('', tk.END, values=(deepcopy(password_dialog.site), deepcopy(password_dialog.username), deepcopy(password_dialog.password)))
    elif action == PW_DEL:
        if guilist.focus() == '':
            return
        selected_item_id = guilist.selection()[0]
        site_name = guilist.item(selected_item_id)['values'][0]
        if mbox.askyesno(title='Delete password', message='Are you sure you want to delete the selected password?\r\n(This cannot be undone)'):
            datastore['store'].pop(site_name, None)
            guilist.delete(selected_item_id)
    else:
        print('ERROR: Unknown action')

def saveDatastore(datastore: dict, store_path='./data/store.pws'):
    with open(store_path, 'w') as store_file:
        store_file.write(dumps(datastore, indent=2))
        store_file.flush()
        print('Datastore saved!')

def saveAndExit(datastore: dict, store_path='./data/store.pws'):
    saveDatastore(datastore, store_path)
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

def searchCallback(datastore: dict, encryption_key:bytes, guilist: ttk.Treeview, search_var: tk.StringVar):
    for child in guilist.get_children():
        guilist.delete(child)
    for site_name in [x for x in datastore['store'].keys() if search_var.get().lower() in x.lower()]:
        entry = deepcopy(datastore['store'][site_name])
        entry_cipher = AES.new(encryption_key, AES.MODE_CBC, iv=b64decode(entry['iv']))
        entry_data = entry_cipher.decrypt(b64decode(entry['data']))
        entry_data = unpad(entry_data, AES.block_size)
        entry_data = loads(entry_data.decode('utf-8'))
        guilist.insert('', tk.END, values=(deepcopy(site_name), deepcopy(entry_data['username']), deepcopy(entry_data['password'])))

def decryptEntry(entry: dict, encryption_key: bytes) -> dict:
    """Decrypt a single password entry"""
    entry_cipher = AES.new(encryption_key, AES.MODE_CBC, iv=b64decode(entry['iv']))
    entry_data = entry_cipher.decrypt(b64decode(entry['data']))
    entry_data = unpad(entry_data, AES.block_size)
    entry_data = loads(entry_data.decode('utf-8'))
    return entry_data

def displayTerminal(datastore: dict, encryption_key: bytes, search_term: str = None):
    """Display passwords in terminal mode"""
    print("\n" + "="*80)
    print(" PASSWORD MANAGER - DATASTORE ENTRIES")
    print("="*80)
    
    entries = []
    for site_name in sorted(datastore['store'].keys()):
        if search_term is None or search_term.lower() in site_name.lower():
            entry_data = decryptEntry(datastore['store'][site_name], encryption_key)
            entries.append({
                'site': site_name,
                'username': entry_data['username'],
                'password': entry_data['password']
            })
    
    if not entries:
        if search_term:
            print(f"\nNo entries found matching '{search_term}'")
        else:
            print("\nNo entries found in datastore")
        return
    
    # Calculate column widths
    max_site = max(len(e['site']) for e in entries)
    max_user = max(len(e['username']) for e in entries)
    max_pass = max(len(e['password']) for e in entries)
    
    # Set minimum column widths
    col_site = max(20, max_site + 2)
    col_user = max(20, max_user + 2)
    col_pass = max(20, max_pass + 2)
    
    # Print header
    print(f"\n{'Site':<{col_site}} {'Username':<{col_user}} {'Password':<{col_pass}}")
    print("-" * (col_site + col_user + col_pass))
    
    # Print entries
    for entry in entries:
        print(f"{entry['site']:<{col_site}} {entry['username']:<{col_user}} {entry['password']:<{col_pass}}")
    
    print(f"\nTotal entries: {len(entries)}")
    print("="*80 + "\n")

def terminalMode(store_path: str, search_term: str = None):
    """Run password manager in terminal mode"""
    # Check if datastore exists
    if not os.path.exists(store_path):
        sys.stderr.write(f"ERROR: Datastore not found at {store_path}\n")
        sys.exit(1)
    
    # Get passphrase from user
    try:
        passphrase = getpass.getpass("Enter passphrase: ")
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)
    
    # Generate key and challenge
    encryption_key = SHA256.new(data=passphrase.encode('utf-8')).digest()
    challenge_string = ''
    for char in passphrase:
        challenge_string += chr(ord(char) ^ 0xff)
    expected_challenge = SHA256.new(data=challenge_string.encode('utf-8')).digest()
    
    # Load and verify datastore
    try:
        with open(store_path, 'r') as store_file:
            datastore = loads(store_file.read())
        initialization_vector = b64decode(datastore['iv'])
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv=initialization_vector)
        challenge_encrypted = b64decode(datastore['challenge'])
        challenge_decrypted = cipher.decrypt(challenge_encrypted)
        challenge_decrypted = unpad(challenge_decrypted, AES.block_size)
        assert expected_challenge == challenge_decrypted, 'Challenge mismatch'
    except ValueError:
        sys.stderr.write('ERROR: Incorrect passphrase\n')
        sys.exit(1)
    except AssertionError as e:
        sys.stderr.write(f'ERROR: Challenge verification failed - {str(e)}\n')
        sys.exit(1)
    
    print('Datastore unlocked successfully!')
    
    # Display entries
    displayTerminal(datastore, encryption_key, search_term)

def parseArgs():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Simple password manager with GUI and terminal modes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                    # Launch GUI with default datastore
  %(prog)s --no-gui           # Display passwords in terminal mode
  %(prog)s -s mystore.pws     # Use a different datastore file
  %(prog)s --no-gui --search github  # Search for entries containing "github"
        '''
    )
    parser.add_argument('-s', '--store', 
                       default='./data/store.pws',
                       help='Path to the password datastore (default: ./data/store.pws)')
    parser.add_argument('--no-gui', action='store_true',
                       help='Run in terminal mode (no GUI)')
    parser.add_argument('--search', type=str,
                       help='Search for entries containing this term (terminal mode only)')
    
    args = parser.parse_args()
    
    # Validate store path
    if not validate_store_path(args.store):
        sys.stderr.write(f"ERROR: Invalid or unsafe store path: {args.store}\n")
        sys.exit(1)
    
    return args

def main():
    'Main entry point'
    
    # Parse command line arguments
    args = parseArgs()
    
    # Handle terminal mode
    if args.no_gui:
        terminalMode(args.store, args.search)
        return
    
    root = tk.Tk()
    root.title('Simple password manager')
    root.minsize(width=800, height=600)
    
    # Set theme (clam is modern and clean)
    style = ttk.Style()
    style.theme_use('clam')
    
    # Check data directory and/or unlock datastore
    key = None
    uchall = None
    
    # Determine store path and data directory
    store_path = args.store
    data_dir = os.path.dirname(store_path) if os.path.dirname(store_path) else './data'
    
    if not os.path.exists(data_dir) or not os.path.exists(store_path):
        initdiag = InitialConfig(root, store_path)
        root.wait_window(initdiag.top)
        key = initdiag.key
        uchall = initdiag.challenge
    else:
        askkey = AskPassphrase(root)
        root.wait_window(askkey.top)
        key = askkey.key
        uchall = askkey.challenge
    try:
        assert key is not None, 'No key provided'
        assert len(key) == 32, 'Incorrect key length'
    except AssertionError as e:
        sys.stderr.write(f'Key error: {str(e)}\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    with open(store_path, 'r') as f:
        datastore = loads(f.read())
    iv = b64decode(datastore['iv'])
    lcipher = AES.new(key, AES.MODE_CBC, iv=iv)
    challenge = b64decode(datastore['challenge'])
    challenge = lcipher.decrypt(challenge)
    try:
        challenge = unpad(challenge, AES.block_size)
        assert uchall == challenge, 'Challenge mismatch'
    except ValueError:
        sys.stderr.write('Incorrect passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    except AssertionError as e:
        sys.stderr.write(f'ERROR: Corrupted datastore\r\nChallenge error: {str(e)}\r\n\r\n')
        sys.exit()
    lcipher = None
    challenge = None
    uchall = None
    print('Datastore unlocked')
    root.attributes('-topmost', True)
    root.attributes('-topmost', False)
    root.protocol('WM_DELETE_WINDOW', lambda: saveAndExit(datastore, store_path))
    # Menus
    menu = tk.Menu(master=root)
    root.config(menu=menu)
    
    filemenu = tk.Menu(master=menu, tearoff=0)
    menu.add_cascade(label='File', menu=filemenu)
    filemenu.add_command(label='Save', command=lambda: saveDatastore(datastore, store_path))
    filemenu.add_command(label='Exit', command=lambda: saveAndExit(datastore, store_path))
    
    viewmenu = tk.Menu(master=menu, tearoff=0)
    menu.add_cascade(label='View', menu=viewmenu)
    
    def change_theme(theme_name):
        style.theme_use(theme_name)
        # Update theme indicator
        for i in range(viewmenu.index(tk.END) + 1):
            viewmenu.entryconfig(i, state='normal')
        print(f'Themed changed to: {theme_name}')
    
    # Theme options
    available_themes = ['clam', 'alt', 'default', 'classic']
    for theme in available_themes:
        viewmenu.add_command(label=f"Theme: {theme}", 
                           command=lambda t=theme: change_theme(t))
    # Toolbar
    toolbar = tk.Frame(root)
    addbtn = ttk.Button(toolbar, text='Add', width=6)
    addbtn.pack(side=tk.LEFT, padx=2, pady=2)
    delbtn = ttk.Button(toolbar, text='Remove', width=6)
    delbtn.pack(side=tk.LEFT, padx=2, pady=2)
    edtbtn = ttk.Button(toolbar, text='Edit', width=6)
    edtbtn.pack(side=tk.LEFT, padx=2, pady=2)
    schlbl = ttk.Label(toolbar, text='Search:', width=8)
    schlbl.pack(side=tk.LEFT, padx=2, pady=2)
    schvar = tk.StringVar(master=toolbar)
    schety = ttk.Entry(master=toolbar, width=32, textvariable=schvar)
    schety.pack(side=tk.LEFT, padx=2)
    cubtn = ttk.Button(toolbar, text='Copy username', width=12)
    cubtn.pack(side=tk.RIGHT, padx=2, pady=2)
    cpbtn = ttk.Button(toolbar, text='Copy password', width=12)
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
    # Search entry callback
    schvar.trace('w', lambda unused_var, unused_idx, unused_mode, ds=datastore, encryption_key=key, lst=listbox, search_var=schvar: searchCallback(ds, encryption_key, lst, search_var))
    root.mainloop()
    saveDatastore(datastore, store_path)

if __name__ == '__main__':
    main()
