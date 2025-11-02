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

from pwmanager.crypto import (
    derive_key
)
from pwmanager.datastore import (
    load_datastore, save_datastore, migrate_legacy_datastore,
    decrypt_entry, encrypt_entry, migrate_datastore_to_gcm,
    verify_passphrase
)
from pwmanager.gui.dialogs import (
    InitialConfig, AskPassphrase, MigrateDialog, PasswordDialog
)

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
            password_list_view.insert('', tk.END, values=(deepcopy(password_dialog.site), deepcopy(password_dialog.username), deepcopy(password_dialog.password)))
    elif action == PASSWORD_ACTION_DELETE:
        if password_list_view.focus() == '':
            return
        selected_item_id = password_list_view.selection()[0]
        site_name = password_list_view.item(selected_item_id)['values'][0]
        if mbox.askyesno(title='Delete password', message='Are you sure you want to delete the selected password?\r\n(This cannot be undone)'):
            datastore['store'].pop(site_name, None)
            password_list_view.delete(selected_item_id)
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


def search_callback(datastore: dict, encryption_key: bytes, password_list_view: ttk.Treeview, search_var: tk.StringVar):
    """Handle search functionality in the GUI."""
    for child in password_list_view.get_children():
        password_list_view.delete(child)
    cipher_mode = datastore['cipher_mode']
    for site_name in [x for x in datastore['store'].keys() if search_var.get().lower() in x.lower()]:
        entry_data = decrypt_entry(datastore['store'][site_name], encryption_key, cipher_mode)
        password_list_view.insert('', tk.END, values=(deepcopy(site_name), deepcopy(entry_data['username']), deepcopy(entry_data['password'])))


def create_main_window(store_path: str):
    """
    Create and run the main GUI window.
    
    Args:
        store_path: Path to the datastore file
    """
    root = tk.Tk()
    root.title('Simple password manager')
    root.minsize(width=800, height=600)
    
    style = ttk.Style()
    style.theme_use('clam')
    
    encryption_key = None
    expected_challenge = None
    
    data_dir = os.path.dirname(store_path) if os.path.dirname(store_path) else './data'
    
    # Initialize or unlock datastore
    if not os.path.exists(data_dir) or not os.path.exists(store_path):
        initial_config_dialog = InitialConfig(root, store_path)
        root.wait_window(initial_config_dialog.top)
        encryption_key = initial_config_dialog.key
        expected_challenge = initial_config_dialog.challenge
    else:
        passphrase_dialog = AskPassphrase(root)
        root.wait_window(passphrase_dialog.top)
        encryption_key = passphrase_dialog.key
        expected_challenge = passphrase_dialog.challenge
    
    try:
        assert encryption_key is not None, 'No encryption key provided'
        assert len(encryption_key) == 32, 'Incorrect encryption key length'
    except AssertionError as e:
        sys.stderr.write(f'Encryption key error: {str(e)}\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    
    datastore = load_datastore(store_path)
    
    was_migrated = migrate_legacy_datastore(datastore)
    if was_migrated:
        save_datastore(datastore, store_path)
    
    # Verify passphrase
    if not verify_passphrase(datastore, encryption_key, expected_challenge):
        sys.stderr.write('Incorrect passphrase\r\nERROR: Unable to unlock datastore\r\n\r\n')
        sys.exit()
    
    # Clear sensitive challenge data (keep encryption_key for operations)
    del expected_challenge
    print('Datastore unlocked')
    
    root.attributes('-topmost', True)
    root.attributes('-topmost', False)
    root.protocol('WM_DELETE_WINDOW', lambda: save_and_exit(datastore, store_path))
    
    # Create menu
    menu = tk.Menu(master=root)
    root.config(menu=menu)
    
    filemenu = tk.Menu(master=menu, tearoff=0)
    menu.add_cascade(label='File', menu=filemenu)
    filemenu.add_command(label='Save', command=lambda: save_datastore(datastore, store_path))
    filemenu.add_command(label='Exit', command=lambda: save_and_exit(datastore, store_path))
    
    viewmenu = tk.Menu(master=menu, tearoff=0)
    menu.add_cascade(label='View', menu=viewmenu)
    
    def change_theme(theme_name):
        style.theme_use(theme_name)
        for i in range(viewmenu.index(tk.END) + 1):
            viewmenu.entryconfig(i, state='normal')
        print(f'Themed changed to: {theme_name}')
    
    available_themes = ['clam', 'alt', 'default', 'classic']
    for theme in available_themes:
        viewmenu.add_command(label=f"Theme: {theme}", 
                           command=lambda t=theme: change_theme(t))
    
    # Create toolbar
    toolbar = tk.Frame(root)
    add_button = ttk.Button(toolbar, text='Add', width=6)
    add_button.pack(side=tk.LEFT, padx=2, pady=2)
    delete_button = ttk.Button(toolbar, text='Remove', width=6)
    delete_button.pack(side=tk.LEFT, padx=2, pady=2)
    edit_button = ttk.Button(toolbar, text='Edit', width=6)
    edit_button.pack(side=tk.LEFT, padx=2, pady=2)
    search_label = ttk.Label(toolbar, text='Search:', width=8)
    search_label.pack(side=tk.LEFT, padx=2, pady=2)
    search_var = tk.StringVar(master=toolbar)
    search_entry = ttk.Entry(master=toolbar, width=32, textvariable=search_var)
    search_entry.pack(side=tk.LEFT, padx=2)
    
    # Migration button - only show if datastore is in CBC mode
    migrate_button = None
    cipher_mode = datastore['cipher_mode']
    if cipher_mode == 'CBC':
        migrate_button = ttk.Button(toolbar, text='Migrate to GCM', width=15)
        migrate_button.pack(side=tk.LEFT, padx=2, pady=2)
    
    copy_username_button = ttk.Button(toolbar, text='Copy username', width=12)
    copy_username_button.pack(side=tk.RIGHT, padx=2, pady=2)
    copy_password_button = ttk.Button(toolbar, text='Copy password', width=12)
    copy_password_button.pack(side=tk.RIGHT, padx=2, pady=2)
    toolbar.pack(side=tk.TOP, fill=tk.X)
    
    # Create list frame
    list_frame = tk.Frame(master=root)
    scrollbar = tk.Scrollbar(master=list_frame, orient=tk.VERTICAL)
    password_list_view = ttk.Treeview(master=list_frame, columns=['site', 'username', 'password'], show='headings', selectmode='browse')
    password_list_view.heading('site', text='Site')
    password_list_view.heading('username', text='Username')
    password_list_view.heading('password', text='Password')
    scrollbar.config(command=password_list_view.yview)
    
    # Load entries into password list view
    for site_name in datastore['store'].keys():
        entry_data = decrypt_entry(datastore['store'][site_name], encryption_key, cipher_mode)
        password_list_view.insert('', tk.END, values=(deepcopy(site_name), deepcopy(entry_data['username']), deepcopy(entry_data['password'])))
    
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    password_list_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
    list_frame.pack(fill=tk.BOTH, expand=1, padx=4, pady=4)
    
    migration_successful = False  # Track if migration succeeded
    
    def handle_migration():
        """Handle migration of datastore from CBC to GCM"""
        nonlocal migration_successful, datastore, encryption_key
        
        migrate_dialog = MigrateDialog(root)
        root.wait_window(migrate_dialog.top)
        
        if migrate_dialog.passphrase is None:
            return  # User cancelled
        
        try:
            migration_key = derive_key(migrate_dialog.passphrase)
            
            # Verify passphrase matches current encryption key
            if migration_key != encryption_key:
                mbox.showerror('Migration Failed', 'Incorrect passphrase')
                return
            
            # Perform migration
            success = migrate_datastore_to_gcm(store_path, migration_key, migrate_dialog.passphrase)
            
            if success:
                # Reload the datastore from disk to get the migrated GCM version
                datastore = load_datastore(store_path)
                
                migration_successful = True
                mbox.showinfo('Migration Successful', 
                            'Datastore migrated to GCM mode successfully!\n'
                            'A backup has been created.\n\n'
                            'Please restart the application to continue.')
                root.quit()
            else:
                mbox.showinfo('Migration Skipped', 'Datastore is already in GCM mode')
        except Exception as e:
            mbox.showerror('Migration Failed', f'Migration failed: {str(e)}')
    
    # Configure button commands
    add_button.config(command=lambda: handle_password(root, datastore, encryption_key, password_list_view, PASSWORD_ACTION_ADD))
    delete_button.config(command=lambda: handle_password(root, datastore, encryption_key, password_list_view, PASSWORD_ACTION_DELETE))
    edit_button.config(command=lambda: handle_password(root, datastore, encryption_key, password_list_view, PASSWORD_ACTION_EDIT))
    copy_username_button.config(command=lambda: copy_to_clipboard(root, password_list_view, CLIPBOARD_COPY_USERNAME))
    copy_password_button.config(command=lambda: copy_to_clipboard(root, password_list_view, CLIPBOARD_COPY_PASSWORD))
    
    if migrate_button is not None:
        migrate_button.config(command=handle_migration)
    
    search_var.trace('w', lambda unused_var, unused_idx, unused_mode, ds=datastore, key=encryption_key, lst=password_list_view, search_var=search_var: search_callback(ds, key, lst, search_var))
    
    root.mainloop()
    
    # Only save if migration didn't happen (migration already saves the datastore)
    if not migration_successful:
        save_datastore(datastore, store_path)


def save_and_exit(datastore: dict, store_path='./data/store.pws'):
    """Save datastore and exit application."""
    save_datastore(datastore, store_path)
    sys.exit(0)

