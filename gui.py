from tkinter import *
from tkinter import ttk
from functools import partial


class windowLayout:
    def __init__(self) -> None:
        root = Tk()
        root.title("ETS project")

        mainframe = ttk.Frame(root, padding="3 3 12 12")
        mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # Alice side
        ttk.Label(mainframe, text="Alice side").grid(column=0, row=0, sticky=W)
        self.alice_text = StringVar()
        alice_text_entry = ttk.Entry(
            mainframe, width=7, textvariable=self.alice_text)
        alice_text_entry.grid(column=0, row=2, sticky=(W, E))
        ttk.Button(mainframe, text="Send to Bert ->", command=partial(self.aliceFunction, "send")).grid(
            column=0, row=3, sticky=W)
        ttk.Button(mainframe, text="Receive <-", command=partial(self.aliceFunction, "receive")).grid(
            column=0, row=4, sticky=W)

        # Bert side
        ttk.Label(mainframe, text="Bert side").grid(column=3, row=0, sticky=E)
        self.bert_text = StringVar()
        bert_text_entry = ttk.Entry(
            mainframe, width=7, textvariable=self.bert_text)
        bert_text_entry.grid(column=3, row=2, sticky=(W, E))
        ttk.Button(mainframe, text="<- Send to Alice", command=partial(self.bertFunction, "send")).grid(
            column=3, row=3, sticky=W)
        ttk.Button(mainframe, text="-> Receive", command=partial(self.bertFunction, "receive")).grid(
            column=3, row=4, sticky=W)

        ttk.Label(mainframe, text="Info box").grid(column=0, row=5, sticky=W)
        self.infoBox = Text(mainframe, height=10, width=50,
                            bg="gray", padx=2, pady=2)
        self.infoBox.grid(column=0, row=6, columnspan=5)

        for child in mainframe.winfo_children():
            child.grid_configure(padx=5, pady=5)

        root.mainloop()

    def aliceFunction(self, *args):
        if len(args):
            if args[0] == 'send':
                text = self.alice_text.get()
                if not text:
                    text = f"[E] Alice's text box is empty\n"
                self.infoBox.insert(
                    END, f"Sending message to Bert: \n\t{text}\n")
            elif args[0] == 'receive':
                text = "Receiving message from Bert ;P..."
                print(text)
                self.infoBox.insert(END, f"{text}\n")
            self.infoBox.see("end")
            self.alice_text.set("")

    def bertFunction(self, *args):
        if len(args):
            if args[0] == 'send':
                text = self.bert_text.get()
                if not text:
                    text = f"[E] Bert's text box is empty\n"
                self.infoBox.insert(
                    END, f"Sending message to Alice: \n\t{text}\n")
            elif args[0] == 'receive':
                text = f"[I] Receiving message from Alice x)..."
                print(text)
                self.infoBox.insert(END, f"{text}\n")
            self.infoBox.see("end")
            self.bert_text.set("")
