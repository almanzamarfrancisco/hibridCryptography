from Crypto.Cipher import AES
from functools import partial
from tkinter import messagebox
from tkinter import ttk
from tkinter import *
import rsa
import os


def init():
    # Make directories and keys if don't exist
    print("\t[I] Checking directories and making keys...")
    if not os.path.exists('./Alice'):
        os.makedirs('./Alice')
    if not os.path.exists('./Bert'):
        os.makedirs('./Bert')
    if not os.path.exists('./Cynthia'):
        os.makedirs('./Cynthia')
    print("\t[I] Directories checked! :)")
    print("\t[I] Making RSA keys...")
    makePairOfKeysFor("Alice", "Bert")
    print("\t[I] Keys check done! :D")


def getRandomBytes(size):
    iv = os.urandom(size)
    print(f"\t[I] Taking random bytes...")
    # print(f"Random bytes are: {iv}")
    # Manually get random bytes from /dev/urandom
    # with open("/dev/random", 'rb') as f:
    # print repr(f.read(10))
    return iv


def AEScipher(data, key, outputfile):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(outputfile, "wb") as ciphered_message_file:
        ciphered_message_file.write(ciphertext)
    with open('./Cynthia/ciphered_message', "wb") as cciphered_message_file:
        cciphered_message_file.write(ciphertext)
    return {"ciphertext": outputfile, "nonce": nonce, "tag": tag, "iv": key}


def AESdecipher(ciphertext, key, tag, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    isAuthentic = False
    try:
        cipher.verify(tag)
        isAuthentic = True
        # print(f"\t[I] The message is authentic! :) ({isAuthentic})")
    except ValueError:
        # print(f"\t[E] Key incorrect or message corrupted :(")
        isAuthentic = False
    return {'plaintext': plaintext.decode(), 'isAuthentic': isAuthentic}


def makePairOfKeysFor(receiver, sender):
    if not os.path.exists(f'./{sender}/rsa'):
        os.makedirs(f'./{sender}/rsa')
    if not os.path.exists(f'./{receiver}/rsa'):
        os.makedirs(f'./{receiver}/rsa')
    if os.path.exists(f"./{sender}/rsa/id_{receiver}_rsa") and os.path.exists(f"./{receiver}/rsa/id_{receiver}_{sender}_rsa.pem"):
        print(
            f"\t\t-> {receiver} => {sender} key files found, skipping creation...")
        return
    (pubkey, privkey) = rsa.newkeys(512)
    try:
        with open(f"./{sender}/rsa/id_{receiver}_rsa", "wb+") as pubfile:
            pubfile.write(pubkey.save_pkcs1())
            print(
                f"\t\t=> id_{receiver}_rsa pubkey generated and saved on {sender} folder")
        with open(f"./{receiver}/rsa/id_{receiver}_{sender}_rsa.pem", "wb+") as privfile:
            privfile.write(privkey.save_pkcs1())
            print(
                f"\t\t=> Privkey generated for {receiver}_{sender} generated")
    except FileExistsError:
        print("\t Something went really wrong! x(")
        pass
    print(f"\t\tDone!")


def getPubkeyFrom(sender, receiver):
    with open(f"./{sender}/rsa/id_{receiver}_rsa", mode='rb') as pubfile:
        keydata = pubfile.read()
        return rsa.PublicKey.load_pkcs1(keydata)


def getPrivateKeyFrom(sender, receiver):
    with open(f"./{receiver}/rsa/id_{receiver}_{sender}_rsa.pem", mode='rb') as privatefile:
        keydata = privatefile.read()
        return rsa.PrivateKey.load_pkcs1(keydata)


def rsaDecryptParameterBytes(ciphered_parameters, privkey):
    parameters = b''
    for i in range(0, len(ciphered_parameters), 64):
        parameters = parameters + \
            rsa.decrypt(ciphered_parameters[i:64+i], privkey)
    # print(f"\t-> Lenght: {len(parameters)} \n\t-> Parameters: {parameters}")
    return parameters


def getListFromBytes(parameters):
    value_ending = 0
    key_ending = 0
    parameters_list = []
    keys_found = 0
    last_key_found = ''
    # print(f"Parameter lenght: {len(parameters)}")
    # len_counter = 0
    # We assume that there are printable and unprintable values on the list (keys are allways printable)
    for i, c in enumerate(parameters):
        if chr(c).isprintable():
            if chr(c) == ':':  # We have a key ending
                key_ending = i + 1
                # print(
                #     f"\tKey found: {parameters[value_ending:i]} => {len(parameters[value_ending:i])}")
                # len_counter = len_counter + len(parameters[value_ending:i])
                last_key_found = (parameters[value_ending:i]).decode()
                parameters_list.append({last_key_found: ''})
                keys_found = keys_found + 1
            elif chr(c) == "^":
                value_ending = i + 1
                # print(
                #     f"\tValue found: {parameters[key_ending:i]} => {len(parameters[key_ending:i])}")
                # len_counter = len_counter + len(parameters[key_ending:i])
                parameters_list[keys_found -
                                1][last_key_found] = parameters[key_ending:i]
                # print()
    # print(f"Total Lenght: {len_counter}")
    # print(f"{parameters_list}")
    return parameters_list


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
        ttk.Button(mainframe, text="Send song to Bert ->", command=partial(self.aliceFunction, "send", "file")).grid(
            column=0, row=4, sticky=W)
        ttk.Button(mainframe, text="Receive from Bert <-", command=partial(self.aliceFunction, "receive")).grid(
            column=0, row=5, sticky=W)

        # Bert side
        ttk.Label(mainframe, text="Bert side").grid(column=3, row=0, sticky=E)
        self.bert_text = StringVar()
        bert_text_entry = ttk.Entry(
            mainframe, width=7, textvariable=self.bert_text)
        bert_text_entry.grid(column=3, row=2, sticky=(W, E))
        ttk.Button(mainframe, text="<- Send to Alice", command=partial(self.bertFunction, "send")).grid(
            column=3, row=3, sticky=W)
        ttk.Button(mainframe, text="-> Receive from Alice", command=partial(self.bertFunction, "receive", "Alice")).grid(
            column=3, row=4, sticky=W)
        ttk.Button(mainframe, text="-> Receive from Cynthia", command=partial(self.bertFunction, "receive", "Cynthia")).grid(
            column=3, row=5, sticky=W)

        # Cynthia side
        ttk.Label(mainframe, text="Cynthia side").grid(
            column=1, row=6, sticky=W)
        self.cynthia_text = StringVar()
        cynthia_text_entry = ttk.Entry(
            mainframe, width=7, textvariable=self.cynthia_text)
        cynthia_text_entry.grid(column=1, row=8, sticky=(W, E))
        ttk.Button(mainframe, text="Send to Bert ->", command=partial(self.cynthiaFunction, "send")).grid(
            column=1, row=9, sticky=W)
        ttk.Button(mainframe, text="() Receive with Bert keys", command=partial(self.cynthiaFunction, "receive", "Bert")).grid(
            column=1, row=10, sticky=W)
        ttk.Button(mainframe, text="() Receive with Cynthia keys", command=partial(self.cynthiaFunction, "receive", "Cynthia")).grid(
            column=1, row=11, sticky=W)

        # Switch
        self.authentic_service_is_on = True
        self.switchLabel = Label(
            mainframe, text="Authenticity service On ", fg="green", font=("Helvetica"))
        self.on = PhotoImage(file="on.png")
        self.off = PhotoImage(file="off.png")
        self.on_button = Button(mainframe, image=self.on,
                                bd=0, command=self.switch)
        self.switchLabel.grid(column=0, row=12)
        self.on_button.grid(column=1, row=12, columnspan=5)

        # Information box
        ttk.Label(mainframe, text="Info box").grid(column=0, row=13, sticky=W)
        self.infoBox = Text(mainframe, height=10, width=50,
                            bg="gray", padx=2, pady=2)
        self.infoBox.grid(column=0, row=14, columnspan=5)

        for child in mainframe.winfo_children():
            child.grid_configure(padx=5, pady=5)

        root.mainloop()

    def switch(self):
        self.authentic_service_is_on
        # Determine is on or off
        if self.authentic_service_is_on:
            self.on_button.config(image=self.off)
            self.switchLabel.config(text="Authenticity service Off", fg="grey")
            self.authentic_service_is_on = False
        else:
            self.on_button.config(image=self.on)
            self.switchLabel.config(
                text="Authenticity service On ", fg="green")
            self.authentic_service_is_on = True

    def sendAMessage(self, sender, receiver, message, *args):
        iv = getRandomBytes(16)
        # AES Ciphering
        if len(args):
            with open(f'{args[0]}', 'rb+') as songfile:
                data = songfile.read()
        else:
            data = bytes(message, 'utf-8')
        parameters = AEScipher(data, iv, f"./{receiver}/ciphered_message")
        # RSA parameter Ciphering
        # Set the parameters on a file
        parameters_bytes = b''
        for k in parameters:
            try:
                parameters_bytes = parameters_bytes + \
                    bytes(k, 'utf-8') + b':' + \
                    bytes(parameters[k], 'utf-8')+b'^'
            except TypeError:
                parameters_bytes = parameters_bytes + \
                    bytes(k, 'utf-8') + b':' + parameters[k] + b'^'
        # Cipher the parameters in a file and send it to the receiver
        self.infoBox.insert(
            END, f"\t[I] Ciphering parameters...\n")
        receiver_pubkey = getPubkeyFrom(sender, receiver)
        with open(f"./{receiver}/ciphered_parameters", "+wb") as ciphered_parameters_file:
            crypto = b''
            # ciphering by 53bytes-size blocks
            for i in range(0, len(parameters_bytes), 54):
                if i == 0:
                    crypto = crypto + \
                        rsa.encrypt(
                            parameters_bytes[i:53+i], receiver_pubkey)
                else:
                    crypto = crypto + \
                        rsa.encrypt(
                            parameters_bytes[i-1:53+i], receiver_pubkey)
            ciphered_parameters_file.write(crypto)
        self.infoBox.insert(
            END, "\t[I] Parameters Ciphered successfully!\n")
        self.infoBox.insert(
            END, "[I] => Message sent!\n")

    def receiveAMessage(self, sender, receiver):
        # Get the cipheredParameters file
        try:
            with open(f"./{receiver}/ciphered_parameters", mode="rb") as cparameter_file:
                ciphered_parameters = cparameter_file.read()
        except FileNotFoundError:
            print("Wait! there is no message to receive x(")
            return
        # Obtain receiver privKey
        privkey = getPrivateKeyFrom(sender, receiver)
        # Decrypt by 64bytes-size blocks
        parameters_in_bytes = rsaDecryptParameterBytes(
            ciphered_parameters, privkey)
        parameters = getListFromBytes(parameters_in_bytes)
        # Get the cipheredMessage file
        with open(f"./{receiver}/ciphered_message", mode="rb") as cmessage_file:
            ciphered_message = cmessage_file.read()
        # Decrypt with obtaned parameters
        message, isAuthentic = AESdecipher(ciphered_message, parameters[3]['iv'],
                                           parameters[2]['tag'], parameters[1]['nonce']).values()
        return {'message': message, 'isAuthentic': isAuthentic}

    def aliceFunction(self, *args):
        if len(args):
            if args[0] == 'send':
                text = self.alice_text.get()
                if not text:
                    text = f"[E] Alice's text box is empty\n"
                    return
                self.infoBox.insert(END, f"Sending message to Bert ...\n")
                if len(args) == 2 and args[1] == 'file':
                    self.sendAMessage('Alice', 'Bert', text,
                                      self.alice_text.get())
                else:
                    self.sendAMessage('Alice', 'Bert', text)
                self.alice_text.set("")
            elif args[0] == 'receive':
                text = f"[I] Receiving message from Bert :B..."
                self.infoBox.insert(END, f"{text}\n")
                try:
                    text, isAuthentic = self.receiveAMessage(
                        'Bert', 'Alice').values()
                except Exception as err:
                    print(str(err))
                    messagebox.showerror(
                        'Error', f'Error: Something went wrong, please send again the last message from Bert x(\n{err}')
                    return
                self.infoBox.insert(END, f"\t -> {text}\n")
                if self.authentic_service_is_on:
                    authenticity_text = f""
                    if isAuthentic:
                        authenticity_text = f"[I] The message is authentic! :D\n"
                    else:
                        authenticity_text = f"[W] Key incorrect or message corrupted x(\n"
                    self.infoBox.insert(
                        END, f"\t{authenticity_text}\n")
            self.infoBox.see("end")

    def bertFunction(self, *args):
        if len(args):
            if args[0] == 'send':
                text = self.bert_text.get()
                if not text:
                    text = f"[E] Bert's text box is empty\n"
                    return
                self.infoBox.insert(
                    END, f"Sending message to Alice ...\n")
                self.sendAMessage('Bert', 'Alice', text)
                self.bert_text.set("")
            elif args[0] == 'receive' and args[1]:
                text = f"[I] Receiving message from Alice x)..."
                self.infoBox.insert(END, f"{text}\n")
                try:
                    text, isAuthentic = self.receiveAMessage(
                        args[1], 'Bert').values()
                except Exception as err:
                    print(str(err))
                    messagebox.showerror(
                        'Error', f'Error: Something went wrong, please send again the last message x(\n{err}')
                    return
                self.infoBox.insert(END, f"\t -> {text}\n")
                if self.authentic_service_is_on:
                    authenticity_text = f""
                    if isAuthentic:
                        authenticity_text = f"[I] The message is authentic! :D\n"
                    else:
                        authenticity_text = f"[W] Key incorrect or message corrupted x(\n"
                    self.infoBox.insert(
                        END, f"\t{authenticity_text}\n")
            else:
                messagebox.showerror(
                    'Error', f"Error: We couldn't know who is sending the message x(\n{err}")
                return
            self.infoBox.see("end")

    def cynthiaFunction(self, *args):
        if len(args):
            if args[0] == 'send':
                text = self.cynthia_text.get()
                if not text:
                    text = f"[E] Cynthia's text box is empty\n"
                    return
                self.infoBox.insert(
                    END, f"Sending message to Bert ...\n")
                self.sendAMessage('Cynthia', 'Bert', text)
                self.cynthia_text.set("")
            elif args[0] == 'receive' and args[1]:
                text = f"[W] Cynthia is receiving a message from Alice :O..."
                self.infoBox.insert(END, f"{text}\n")
                try:
                    text, isAuthentic = self.receiveAMessage(
                        "Alice", args[1]).values()
                except Exception as err:
                    print(str(err))
                    messagebox.showerror(
                        'Error', f'Error: Something went wrong x( :\n{err}')
                    return
                self.infoBox.insert(END, f"\t -> {text}\n")
                if self.authentic_service_is_on:
                    authenticity_text = f""
                    if isAuthentic:
                        authenticity_text = f"[I] The message is authentic! :D\n"
                    else:
                        authenticity_text = f"[W] Key incorrect or message corrupted x(\n"
                    self.infoBox.insert(
                        END, f"\t{authenticity_text}\n")
            else:
                messagebox.showerror(
                    'Error', f"Error: We couldn't know witch Keys we have to use x(\n")
                return
            self.infoBox.see("end")


if __name__ == '__main__':
    print("\n\n**ETS Project**")
    init()
    windowLayout()
