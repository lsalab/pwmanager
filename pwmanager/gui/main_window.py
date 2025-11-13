"""
Main GUI window for password manager.

Handles the main application window and all GUI operations.
"""

import sys
import os
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as mbox
from json import loads
from base64 import b64decode
from copy import deepcopy

from pwmanager.datastore import (
    load_datastore, save_datastore,
    decrypt_entry, encrypt_entry,
    verify_passphrase, get_encryption_key_from_datastore
)
from pwmanager.gui.dialogs import (
    InitialConfig, AskPassphrase, PasswordDialog
)
from pwmanager.gui.styles import (
    configure_main_window_styles, StylingColors
)
from pwmanager.gui.rounded_button import RoundedButton

# Constants for password actions
PASSWORD_ACTION_ADD = 0
PASSWORD_ACTION_DELETE = 1
PASSWORD_ACTION_EDIT = 2

# Constants for clipboard actions
CLIPBOARD_COPY_USERNAME = 0
CLIPBOARD_COPY_PASSWORD = 1


def handle_password(master: tk.Tk, datastore: dict, encryption_key: bytes, password_list_view: ttk.Treeview, action: int):
    """Handle password add, edit, or delete operations."""
    if action in [PASSWORD_ACTION_ADD, PASSWORD_ACTION_EDIT]:
        password_dialog = None
        if action == PASSWORD_ACTION_ADD:
            password_dialog = PasswordDialog(master)
        else:
            if password_list_view.focus() == '':
                return
            selected_item_id = password_list_view.selection()[0]
            selected_item = password_list_view.item(selected_item_id)
            selected_values = selected_item['values']
            old_site = selected_values[0]
            old_username = selected_values[1]
            old_password = selected_values[2]
            password_dialog = PasswordDialog(master, site=deepcopy(old_site), username=deepcopy(old_username), password=deepcopy(old_password))
            password_dialog.site_entry.config(state=tk.DISABLED)
            password_dialog.username_entry.config(state=tk.DISABLED)
            password_dialog.password_entry.focus_set()
            password_list_view.delete(selected_item_id)
            del old_site
            del old_username
            del old_password
            del selected_values
        master.wait_window(password_dialog.top)
        if password_dialog.ok_pressed and password_dialog.site.strip() != '':
            datastore['store'].pop(password_dialog.site, None)
            cipher_mode = datastore['cipher_mode']
            entry = encrypt_entry(
                password_dialog.username,
                password_dialog.password,
                encryption_key,
                cipher_mode
            )
            datastore['store'][password_dialog.site] = deepcopy(entry)
            # Reload and sort the treeview
            reload_treeview(datastore, encryption_key, password_list_view)
    elif action == PASSWORD_ACTION_DELETE:
        if password_list_view.focus() == '':
            return
        selected_item_id = password_list_view.selection()[0]
        site_name = password_list_view.item(selected_item_id)['values'][0]
        if mbox.askyesno(title='Delete password', message='Are you sure you want to delete the selected password?\r\n(This cannot be undone)'):
            datastore['store'].pop(site_name, None)
            # Reload and sort the treeview
            reload_treeview(datastore, encryption_key, password_list_view)
    else:
        print('ERROR: Unknown action')


def copy_to_clipboard(master: tk.Tk, password_list_view: ttk.Treeview, copy_type: int):
    """Copy username or password to clipboard."""
    if password_list_view.focus() == '':
        return
    item_id = password_list_view.selection()[0]
    values = password_list_view.item(item_id)['values']
    master.clipboard_clear()
    if copy_type == CLIPBOARD_COPY_USERNAME:
        master.clipboard_append(values[1])
    elif copy_type == CLIPBOARD_COPY_PASSWORD:
        master.clipboard_append(values[2])
    else:
        print('Unknown copy type')
    master.update()


def reload_treeview(datastore: dict, encryption_key: bytes, password_list_view: ttk.Treeview, search_var: tk.StringVar = None):
    """
    Reload and sort Treeview entries by website name.
    
    Args:
        datastore: The datastore dictionary
        encryption_key: Encryption key for decrypting entries
        password_list_view: The Treeview widget to populate
        search_var: Optional search variable to filter results
    """
    # Clear existing entries
    for child in password_list_view.get_children():
        password_list_view.delete(child)
    
    cipher_mode = datastore['cipher_mode']
    
    # Get all site names
    site_names = list(datastore['store'].keys())
    
    # Apply search filter if provided
    if search_var and search_var.get():
        search_term = search_var.get().lower()
        site_names = [x for x in site_names if search_term in x.lower()]
    
    # Sort site names alphabetically (case-insensitive)
    site_names.sort(key=str.lower)
    
    # Insert entries in sorted order
    for site_name in site_names:
        entry_data = decrypt_entry(datastore['store'][site_name], encryption_key, cipher_mode)
        password_list_view.insert('', tk.END, values=(deepcopy(site_name), deepcopy(entry_data['username']), deepcopy(entry_data['password'])))


def search_callback(datastore: dict, encryption_key: bytes, password_list_view: ttk.Treeview, search_var: tk.StringVar):
    """Handle search functionality in the GUI."""
    reload_treeview(datastore, encryption_key, password_list_view, search_var)


def create_main_window(store_path: str):
    """
    Create and run the main GUI window.
    
    Args:
        store_path: Path to the datastore file
    """
    root = tk.Tk()
    root.title('Password Manager')
    root.minsize(width=1000, height=700)
    root.geometry('1000x700')
    
    # Configure modern ttk styles
    style = ttk.Style()
    configure_main_window_styles(root, style)
    
    data_dir = os.path.dirname(store_path) if os.path.dirname(store_path) else './data'
    
    # Initialize or unlock datastore
    if not os.path.exists(data_dir) or not os.path.exists(store_path):
        initial_config_dialog = InitialConfig(root, store_path)
        root.wait_window(initial_config_dialog.top)
        # Datastore is now initialized with PBKDF2, reload it
        datastore = load_datastore(store_path)
        passphrase = initial_config_dialog.passphrase_entry1.get()
        encryption_key = get_encryption_key_from_datastore(datastore, passphrase)
    else:
        ask_passphrase = AskPassphrase(root)
        root.wait_window(ask_passphrase.top)
        
        if not ask_passphrase.passphrase:
            sys.stderr.write('No passphrase provided\r\nERROR: Unable to unlock datastore\r\n\r\n')
            sys.exit()
        
        datastore = load_datastore(store_path)
        
        # Verify passphrase
        if not verify_passphrase(datastore, ask_passphrase.passphrase):
            sys.stderr.write('Incorrect passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')
            sys.exit()
        
        # Get encryption key using datastore's key derivation method
        encryption_key = get_encryption_key_from_datastore(datastore, ask_passphrase.passphrase)
    
    print('Datastore unlocked')
    
    root.attributes('-topmost', True)
    root.attributes('-topmost', False)
    root.protocol('WM_DELETE_WINDOW', lambda: save_and_exit(datastore, store_path))
    
    # Create toolbar with modern layout
    toolbar = ttk.Frame(root, style='TFrame')
    toolbar.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
    
    # Left side: Action buttons
    action_frame = ttk.Frame(toolbar, style='TFrame')
    action_frame.pack(side=tk.LEFT)
    
    add_button = RoundedButton(action_frame, text='Add', width=80,
                               bg_color=StylingColors.ACCENT.value,
                               hover_color=StylingColors.HOVER.value,
                               canvas_bg=StylingColors.BG.value)
    add_button.pack(side=tk.LEFT, padx=3)
    edit_button = RoundedButton(action_frame, text='Edit', width=80,
                               bg_color=StylingColors.ACCENT.value,
                               hover_color=StylingColors.HOVER.value,
                               canvas_bg=StylingColors.BG.value)
    edit_button.pack(side=tk.LEFT, padx=3)
    delete_button = RoundedButton(action_frame, text='Remove', width=90,
                                 bg_color=StylingColors.ACCENT.value,
                                 hover_color=StylingColors.HOVER.value,
                                 canvas_bg=StylingColors.BG.value)
    delete_button.pack(side=tk.LEFT, padx=3)
    
    # Center: Search
    search_frame = ttk.Frame(toolbar, style='TFrame')
    search_frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=20)
    search_label = ttk.Label(search_frame, text='Search:', width=8)
    search_label.pack(side=tk.LEFT, padx=(0, 5))
    search_var = tk.StringVar(master=search_frame)
    search_entry = ttk.Entry(master=search_frame, width=30, textvariable=search_var)
    search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    # Right side: Copy buttons
    copy_frame = ttk.Frame(toolbar, style='TFrame')
    copy_frame.pack(side=tk.RIGHT)
    
    copy_username_button = RoundedButton(copy_frame, text='Copy Username', width=130,
                                         bg_color=StylingColors.ACCENT.value,
                                         hover_color=StylingColors.HOVER.value,
                                         canvas_bg=StylingColors.BG.value)
    copy_username_button.pack(side=tk.LEFT, padx=3)
    copy_password_button = RoundedButton(copy_frame, text='Copy Password', width=130,
                                        bg_color=StylingColors.ACCENT.value,
                                        hover_color=StylingColors.HOVER.value,
                                        canvas_bg=StylingColors.BG.value)
    copy_password_button.pack(side=tk.LEFT, padx=3)
    
    cipher_mode = datastore['cipher_mode']
    
    # Create list frame with modern styling
    list_frame = ttk.Frame(master=root, style='TFrame')
    list_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=(0, 10))
    
    # Create scrollbar
    scrollbar = ttk.Scrollbar(master=list_frame, orient=tk.VERTICAL)
    
    # Create treeview with better column configuration
    password_list_view = ttk.Treeview(master=list_frame, 
                                      columns=['site', 'username', 'password'], 
                                      show='headings', 
                                      selectmode='browse',
                                      yscrollcommand=scrollbar.set)
    
    # Configure columns with appropriate widths
    password_list_view.heading('site', text='Website/Service')
    password_list_view.heading('username', text='Username')
    password_list_view.heading('password', text='Password')
    
    password_list_view.column('site', width=300, anchor=tk.W)
    password_list_view.column('username', width=250, anchor=tk.W)
    password_list_view.column('password', width=300, anchor=tk.W)
    
    scrollbar.config(command=password_list_view.yview)
    
    # Load entries into password list view (sorted by website name)
    reload_treeview(datastore, encryption_key, password_list_view)
    
    # Pack scrollbar and treeview
    password_list_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Configure button commands
    add_button.config(command=lambda: handle_password(root, datastore, encryption_key, password_list_view, PASSWORD_ACTION_ADD))
    delete_button.config(command=lambda: handle_password(root, datastore, encryption_key, password_list_view, PASSWORD_ACTION_DELETE))
    edit_button.config(command=lambda: handle_password(root, datastore, encryption_key, password_list_view, PASSWORD_ACTION_EDIT))
    copy_username_button.config(command=lambda: copy_to_clipboard(root, password_list_view, CLIPBOARD_COPY_USERNAME))
    copy_password_button.config(command=lambda: copy_to_clipboard(root, password_list_view, CLIPBOARD_COPY_PASSWORD))
    
    search_var.trace('w', lambda unused_var, unused_idx, unused_mode, ds=datastore, key=encryption_key, lst=password_list_view, search_var=search_var: search_callback(ds, key, lst, search_var))
    
    root.mainloop()
    
    save_datastore(datastore, store_path)


def save_and_exit(datastore: dict, store_path='./data/store.pws'):
    """Save datastore and exit application."""
    save_datastore(datastore, store_path)
    sys.exit(0)

