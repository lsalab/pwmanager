#!/usr/bin/env python3
'Simple password manager'

import sys
import tkinter as tk

def main():
    'Main entry point'
    root = tk.Tk()
    root.wm_title(string='Simple password manager')
    root.wm_minsize(width=800, height=600)
    # Menus
    menu = tk.Menu(master=root)
    root.config(menu=menu)
    filemenu = tk.Menu(master=menu)
    menu.add_cascade(label='File', menu=filemenu)
    filemenu.add_command(label='Exit', command=sys.exit)
    # List box
    listbox = tk.Listbox(master=root)
    listbox.config()
    listbox.grid(row=0, column=0, sticky=tk.W + tk.NS)
    for i in range(20):
        listbox.insert(listbox.size(), 'test')
    print(root.grid_size())
    root.mainloop()

if __name__ == '__main__':
    main()
