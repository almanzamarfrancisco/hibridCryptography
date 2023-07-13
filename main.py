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
    makeKeysForPerson("Alice")
    makeKeysForPerson("Bert")
    makeKeysForPerson("Cynthia")
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


def makeKeysForPerson(person):
    if not os.path.exists(f'./{person}/rsa'):
        os.makedirs(f'./{person}/rsa')
    if os.path.exists(f"./{person}/rsa/id_rsa") and os.path.exists(f"./{person}/rsa/id_rsa.pem"):
        print(f"\t\t -> {person} key files found, skipping creation...")
        return
    (pubkey, privkey) = rsa.newkeys(512)
    try:
        with open(f"./{person}/rsa/id_rsa", "wb+") as pubfile:
            pubfile.write(pubkey.save_pkcs1())
            print(f"\t\t=> {person} pubkey generated")
        with open(f"./{person}/rsa/id_rsa.pem", "wb+") as privfile:
            privfile.write(privkey.save_pkcs1())
    except FileExistsError:
        print("\t Something went really wrong! x(")
        pass
    print(f"\t\t=> {person} pubkey generated")


def getPubkeyFromPerson(person):
    with open(f"./{person}/rsa/id_rsa", mode='rb') as pubfile:
        keydata = pubfile.read()
        return rsa.PublicKey.load_pkcs1(keydata)


def getPrivateKeyFromPerson(person):
    with open(f"./{person}/rsa/id_rsa.pem", mode='rb') as privatefile:
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

        # Cynthia side
        ttk.Label(mainframe, text="Cynthia side").grid(
            column=1, row=5, sticky=W)
        self.cynthia_text = StringVar()
        cynthia_text_entry = ttk.Entry(
            mainframe, width=7, textvariable=self.cynthia_text)
        cynthia_text_entry.grid(column=1, row=6, sticky=(W, E))
        ttk.Button(mainframe, text="Send to Bert ->", command=partial(self.cynthiaFunction, "send")).grid(
            column=1, row=7, sticky=W)
        ttk.Button(mainframe, text="() Receive with Bert keys", command=partial(self.bertFunction, "receive")).grid(
            column=1, row=8, sticky=W)
        ttk.Button(mainframe, text="() Receive with Cynthia keys", command=partial(self.cynthiaFunction, "receive")).grid(
            column=1, row=9, sticky=W)

        # Switch
        self.authentic_service_is_on = True
        self.switchLabel = Label(
            mainframe, text="Authenticity service On ", fg="green", font=("Helvetica"))
        self.on = PhotoImage(file="on.png")
        self.off = PhotoImage(file="off.png")
        self.on_button = Button(mainframe, image=self.on,
                                bd=0, command=self.switch)
        self.switchLabel.grid(column=0, row=10)
        self.on_button.grid(column=1, row=10, columnspan=5)

        # Information box
        ttk.Label(mainframe, text="Info box").grid(column=0, row=11, sticky=W)
        self.infoBox = Text(mainframe, height=10, width=50,
                            bg="gray", padx=2, pady=2)
        self.infoBox.grid(column=0, row=11, columnspan=5)

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

    def sendAMessage(self, sender, receiver, message):
        data = bytes(message, 'utf-8')
        iv = getRandomBytes(16)
        # AES Ciphering
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
        receiver_pubkey = getPubkeyFromPerson(receiver)
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
        with open(f"./Cynthia/ciphered_parameters", "+wb") as cciphered_parameters_file:
            cciphered_parameters_file.write(crypto)
        self.infoBox.insert(
            END, "\t[I] Parameters Ciphered successfully!\n")
        self.infoBox.insert(
            END, "[I] => Message sent!\n")

    def receiveAMessage(self, receiver):
        # Get the cipheredParameters file
        try:
            with open(f"./{receiver}/ciphered_parameters", mode="rb") as cparameter_file:
                ciphered_parameters = cparameter_file.read()
        except FileNotFoundError:
            print("Wait! there is no message to receive x(")
            return
        # Obtain receiver privKey
        with open(f"./{receiver}/rsa/id_rsa.pem", mode='rb') as privatefile:
            keydata = privatefile.read()
        privkey = rsa.PrivateKey.load_pkcs1(keydata)
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
                self.infoBox.insert(
                    END, f"Sending message to Bert ...\n")
                self.sendAMessage('Alice', 'Bert', text)
                self.alice_text.set("")
            elif args[0] == 'receive':
                text = f"[I] Receiving message from Bert :B..."
                self.infoBox.insert(END, f"{text}\n")
                try:
                    text, isAuthentic = self.receiveAMessage('Alice').values()
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
            elif args[0] == 'receive':
                text = f"[I] Receiving message from Alice x)..."
                self.infoBox.insert(END, f"{text}\n")
                try:
                    text, isAuthentic = self.receiveAMessage('Bert').values()
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

    def cynthiaFunction(self, *args):
        if len(args):
            if args[0] == 'send':
                text = self.cynthia_text.get()
                if not text:
                    text = f"[E] Cynthia's text box is empty\n"
                    return
                self.infoBox.insert(
                    END, f"Sending message to Bert ...\n")
                self.sendAMessage('Cinthia', 'Bert', text)
                self.cynthia_text.set("")
            if args[0] == 'receive':
                text = f"[W] Cinthia is receiving a message from Alice :O..."
                self.infoBox.insert(END, f"{text}\n")
                try:
                    text, isAuthentic = self.receiveAMessage(
                        'Cynthia').values()
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
            self.infoBox.see("end")
        pass


if __name__ == '__main__':
    print("\n\n**ETS Project**")
    init()
    windowLayout()
