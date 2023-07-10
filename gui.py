from tkinter import *
from tkinter import ttk
from functools import partial


def aliceFunction(*args):
    if len(args):
        if args[0] == 'send':
            print("Send to Bert :)")
        elif args[0] == 'receive':
            print("Receive from Bert B)")


def bertFunction(*args):
    if len(args):
        if args[0] == 'send':
            print("Send to Alice :P)")
        elif args[0] == 'receive':
            print("Receive from Alice :B)")


def generateWindow():
    root = Tk()
    root.title("ETS project")

    mainframe = ttk.Frame(root, padding="3 3 12 12")
    mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    # Alice side
    ttk.Label(mainframe, text="Alice side").grid(column=0, row=0, sticky=W)
    alice_text = StringVar()
    alice_text_entry = ttk.Entry(mainframe, width=7, textvariable=alice_text)
    alice_text_entry.grid(column=0, row=2, sticky=(W, E))
    ttk.Button(mainframe, text="Send to Bert ->", command=partial(aliceFunction, "send")).grid(
        column=0, row=3, sticky=W)
    ttk.Button(mainframe, text="Receive <-", command=partial(aliceFunction, "receive")).grid(
        column=0, row=4, sticky=W)

    # Bert side
    ttk.Label(mainframe, text="Bert side").grid(column=3, row=0, sticky=E)
    bert_text = StringVar()
    bert_text_entry = ttk.Entry(mainframe, width=7, textvariable=bert_text)
    bert_text_entry.grid(column=3, row=2, sticky=(W, E))
    ttk.Button(mainframe, text="<- Send to Alice", command=partial(bertFunction, "send")).grid(
        column=3, row=3, sticky=W)
    ttk.Button(mainframe, text="-> Receive", command=partial(bertFunction, "receive")).grid(
        column=3, row=4, sticky=W)

    ttk.Label(mainframe, text="Info box").grid(column=0, row=5, sticky=W)

    for child in mainframe.winfo_children():
        child.grid_configure(padx=5, pady=5)

    # feet_entry.focus()
    # root.bind("<Return>", calculate)

    root.mainloop()
