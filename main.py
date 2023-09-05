from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from functools import partial
from tkinter import messagebox
from tkinter import ttk
from tkinter import *
from tkinter import filedialog as fd
from hashlib import sha512
import rsa
import os


def init():
    # Make directories and keys if don't exist
    makePairOfKeys()

def getRandomBytes(size):
    iv = os.urandom(size)
    print(f"\t[I] Taking random bytes...")
    # print(f"Random bytes are: {iv}")
    # Manually get random bytes from /dev/urandom
    # with open("/dev/random", 'rb') as f:
    # print repr(f.read(10))
    return iv


def AEScipher(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext


def AESdecipher(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def makePairOfKeys():
    if not os.path.exists(f'./rsa'):
        os.makedirs(f'./rsa')
    if os.path.exists(f"./rsa/a_pubkey_rsa") and os.path.exists(f"./rsa/a_privkey_rsa.pem") and os.path.exists(f"./rsa/b_pubkey_rsa") and os.path.exists(f"./rsa/b_privkey_rsa.pem"):
        print(f"\t\t-> key files found, skipping creation...")
        return
    try:
        # RSA with signature
        keyPair = RSA.generate(bits=1024)
        with open(f"./rsa/a_pubkey_rsa", "w+") as pubfile:
            pubfile.write(f"-----RSA Public Key-----\n{hex(keyPair.e)}\n\n{keyPair.n}\n-----RSA Public Key END-----")
            print(f"\t\t=> A pubkey generated and saved on rsa folder")
        with open(f"./rsa/a_privkey_rsa.pem", "w+") as privfile:
            privfile.write(f"-----RSA Private Key-----\n{hex(keyPair.d)}\n\n{keyPair.n}\n-----RSA Private Key END-----")
            print(f"\t\t=> A privkey generated on rsa generated")

        # RSA without signature
        (b_pubkey, b_privkey) = rsa.newkeys(512)
        with open(f"./rsa/b_pubkey_rsa", "wb+") as pubfile:
            pubfile.write(b_pubkey.save_pkcs1())
            print(f"\t\t=> B pubkey generated and saved on rsa folder")
        with open(f"./rsa/b_privkey_rsa.pem", "wb+") as privfile:
            privfile.write(b_privkey.save_pkcs1())
            print(f"\t\t=> B privkey generated on rsa generated")
    except FileExistsError:
        print("\t Something went really wrong! x(")
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
        mainframe.grid(column=0, row=0, sticky=(N, W, E, S)) # type: ignore
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # Interface
        ttk.Label(mainframe, text="Press next button to choose the action you want to do").grid(column=0, row=0, sticky=W)
        
        # Switch
        self.action_switch = True
        self.switchLabel = Label(mainframe, text="Action: ", font=("Helvetica"))
        self.switchLabel.grid(column=0, row=1)
        self.switch_button = Button(mainframe, text="Encrypt", bd=0, command=self.switch)
        self.switch_button.grid(column=0, row=2)

        # Checkboxes
        self.sign_value = IntVar()
        self.verification_value = IntVar()
        self.sing_check = Checkbutton(mainframe, text = "Signing", variable = self.sign_value,onvalue = 1, offvalue = 0, height=1, width = 10)
        self.sign_verification = Checkbutton(mainframe, text = "Varification", variable = self.verification_value, onvalue = 1, offvalue = 0, height=1, width = 10)
        self.sing_check.grid(column=0, row=3)
        self.sign_verification.grid(column=0, row=4)

        # Key File selection
        self.key_file_selection = Button(mainframe, text="Select the key file", bd=0, command=partial(self.select_file,"key"))
        self.key_file_selection.grid(column=0, row=5)
        self.key_filename_text = StringVar()
        key_filename_text_entry = ttk.Entry(mainframe, width=6, textvariable=self.key_filename_text)
        key_filename_text_entry.grid(column=0, row=7, sticky=(W, E)) # type: ignore

        # File selection
        self.file_selection = Button(mainframe, text="Select a file", bd=0, command=partial(self.select_file, "song"))
        self.file_selection.grid(column=0, row=8)
        self.filename_text = StringVar()
        filename_text_entry = ttk.Entry(mainframe, width=5, textvariable=self.filename_text)
        filename_text_entry.grid(column=0, row=9, sticky=(W, E)) # type: ignore

        # Do it button
        self.action_button = Button(mainframe, text="Do it!", bd=0, command=partial(self.action, "arg"))
        self.action_button.grid(column=0, row=10)

        # Information box
        ttk.Label(mainframe, text="Info box").grid(column=0, row=11, sticky=W)
        self.infoBox = Text(mainframe, height=10, width=50,bg="gray", padx=2, pady=2)
        self.infoBox.grid(column=0, row=12, columnspan=5)

        for child in mainframe.winfo_children():
            child.grid_configure(padx=5, pady=5)

        root.mainloop()

    def switch(self): # self.action_switch True = Encrypt | False = Decrypt
        # Determine is encrypt or decrypt
        if self.action_switch:
            self.switch_button.config(text="Decrypt")
            self.action_switch = False
        else:
            self.switch_button.config(text="Encrypt")
            self.action_switch = True

    def select_file(self, args):
        filetypes = (
            ('All files', '*'),
        )
        filename = fd.askopenfilename(
            title='Open a file',
            initialdir=os.path.dirname(os.path.realpath(__file__)),
            filetypes=filetypes)
        if args == 'song':
            self.filename_text.set(filename)
        elif args == 'key':
            self.key_filename_text.set(filename)
            
    def action(self, *args):
        # print("Action gotten")
        # print(f"Variables values: \n\tSwitchButton: {self.action_switch} \n\tSigning: {self.sign_value.get()}, \n\tVer: {self.verification_value.get()}")
        if self.action_switch: # Encrypt
            self.encrypt(self.filename_text.get())
        else: # Decrypt
            self.decrypt(self.filename_text.get())   
    def encrypt(self, filename, *args):
        AES_key = getRandomBytes(16)
        with open(filename, mode='rb') as file:
            data = file.read()
        # AES Ciphering
        cipher_text = AEScipher(data, AES_key)
        # print(cipher_text)
        # RSA Encryption for AES Key
        with open(f'./rsa/b_pubkey_rsa', mode='rb') as pubfile: # Bert Public key selected by default
            keydata = pubfile.read()
        pubkey = rsa.PublicKey.load_pkcs1(keydata)
        ciphered_key = rsa.encrypt(AES_key, pubkey)
        # print("AES key Encrypted\n\t",ciphered_key)
        # RSA Encryption for digital sign
        print("\nLet's take 21 elements\n",data[:21])
        hash = int.from_bytes(sha512(data[:21]).digest(), byteorder='big')
        with open(self.key_filename_text.get(), mode='r') as privfile: # User select private key
            keydata = privfile.read()
        n_start = keydata.find("\n\n")+2
        n = int(keydata[n_start:keydata.find("-----RSA Private Key END-----")], 16)
        d = int(keydata[keydata.find("\n\n") -1:keydata.find("\n\n")], 16)
        signature = pow(hash, d, n)
        # print(f"Signature: {hex(signature)}")
        with open(f"./signature", "w+") as signaturefile:
            signaturefile.write(f"{hex(signature)}")
        with open(f"./output", "wb+") as outputfile:
            outputfile.write(ciphered_key+b"\n\n"+cipher_text)
        self.infoBox.insert(END, "\n[I] Encryption Done!\n")
        self.filename_text.set("")
        self.key_filename_text.set("")

    def decrypt(self, filename):
       # RSA decrypt for AES key
        with open(self.key_filename_text.get(), mode='rb') as privatefile:
            keydata = privatefile.read()
            privkey = rsa.PrivateKey.load_pkcs1(keydata)
        with open(self.filename_text.get(), mode='rb+') as cipheredfile:
            data = cipheredfile.read()
        ciphered_key = data[:data.find(b"\n\n")]
        deciphered_key = rsa.decrypt(ciphered_key, privkey)
        ciphered_text = data[data.find(b"\n\n")+2:]
        # AES decryption
        plaintext = AESdecipher(ciphered_text, deciphered_key)
        print(plaintext)
        with open(f"./plaintext.txt", "wb+") as outputfile:
            outputfile.write(plaintext)
        # RSA Decryption for digital sign
        
    

if __name__ == '__main__':
    print("\n\n**ETS Project**")
    init()
    windowLayout()
