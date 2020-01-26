#!/usr/bin/env python3
'Simple password manager'

import os
import sys
import json
import tkinter as tk

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
        ppstat = self.ppstat = tk.Label(top, text ='')
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
            return True
        else:
            self.okbtn.config(state=tk.DISABLED)
            return False

    def ok(self):
        self.top.grab_release()
        self.top.destroy()

def main():
    'Main entry point'

    root = tk.Tk()
    root.wm_title(string='Simple password manager')
    root.wm_minsize(width=800, height=600)
    # Check data directory
    if not os.path.exists('./data'):
        initdiag = InitialConfig(root)
        root.wait_window(initdiag.top)
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
    listbox = tk.Listbox(master=root)
    listbox.pack(fill=tk.BOTH, expand=1)
    root.mainloop()

if __name__ == '__main__':
    main()
