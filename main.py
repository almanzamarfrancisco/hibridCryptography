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
        print("=> rsa folder not found. Generating keys ...")
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

        # Checkbox
        self.sign_value = IntVar()
        self.sing_check = Checkbutton(mainframe, text = "Signing/Verification", variable = self.sign_value,onvalue = 1, offvalue = 0, height=1, width = 20)
        self.sing_check.grid(column=0, row=3, columnspan=10)

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
        if self.action_switch: # Encrypt
            self.encrypt(self.filename_text.get())
        else: # Decrypt
            self.decrypt(self.filename_text.get())   

    def encrypt(self, filename, *args):
        AES_key = getRandomBytes(16)
        self.infoBox.insert(END, "[I] Obtaining data file ...\n")
        with open(filename, mode='rb') as file:
            data = file.read()
        # AES Ciphering
        self.infoBox.insert(END, "[I] Ciphering with AES ...\n")
        cipher_text = AEScipher(getRandomBytes(16)+data, AES_key) # Padding of 16 bytes
        # RSA Encryption for AES Key
        self.infoBox.insert(END, "[I] Obtaining public key ... \n")
        with open(f'./rsa/b_pubkey_rsa', mode='rb') as pubfile: # Public key selected by default
            keydata = pubfile.read()
        pubkey = rsa.PublicKey.load_pkcs1(keydata)
        self.infoBox.insert(END, "[I] Ciphering with RSA ...\n")
        ciphered_key = rsa.encrypt(AES_key, pubkey)
        # RSA Encryption for digital sign
        if self.sign_value.get():
            # print("\nLet's take 32 elements\n",data[:32])
            hash = int.from_bytes(sha512(data[:32]).digest(), byteorder='big')
            self.infoBox.insert(END, "[I] Obtaining privatekey for singnature ... \n")
            with open(self.key_filename_text.get(), mode='r') as privfile: # User select private key
                keydata = privfile.read()
            n_start = keydata.find("\n\n")+2
            n = int(keydata[n_start:keydata.find("-----RSA Private Key END-----")], 16)
            d = int(keydata[keydata.find("\n\n") -1:keydata.find("\n\n")], 16)
            signature = pow(hash, d, n)
            self.infoBox.insert(END, "[I] Singning file ...\n")
            with open(f"./signature", "w+") as signaturefile:
                signaturefile.write(f"{hex(signature)}")
            self.infoBox.insert(END, "[I] Done!\n")
        with open(f"./output", "wb+") as outputfile:
            outputfile.write(ciphered_key+b"\n\n"+cipher_text)
        self.infoBox.insert(END, "[I] Encryption Done!\n\n\n")
        self.filename_text.set("")
        self.key_filename_text.set("")

    def decrypt(self, filename):
       # RSA decrypt for AES key
        self.infoBox.insert(END, "[I] Obtaining private key file ...\n")
        with open(self.key_filename_text.get(), mode='rb') as privatefile:
            keydata = privatefile.read()
            privkey = rsa.PrivateKey.load_pkcs1(keydata)
        with open(self.filename_text.get(), mode='rb+') as cipheredfile:
            data = cipheredfile.read()
        self.infoBox.insert(END, "[I] Deciphering with RSA...\n")
        ciphered_key = data[:data.find(b"\n\n")]
        try:
            deciphered_key = rsa.decrypt(ciphered_key, privkey)
        except Exception as err:
            messagebox.showerror('Error', f'Error: To decipher the key x(\n{err}')
            self.infoBox.insert(END, f"[E] To decipher the key x(\n\n\t{err}\n")
            return
        ciphered_text = data[data.find(b"\n\n")+2:]
        # AES decryption
        try:
            plaintext = AESdecipher(ciphered_text, deciphered_key)
        except Exception as err:
            messagebox.showerror('Error', f'Error: To decipher the file x(\n{err}')
            self.infoBox.insert(END, f"[E] To decipher the file x(\n\n\t{err}")
            return
        plaintext = plaintext[16:] # padding from encryption
        print(plaintext)
        self.infoBox.insert(END, "[I] Deciphering with AES...\n")
        with open(f"./plaintext.txt", "wb+") as outputfile:
            outputfile.write(plaintext)
        # RSA Decryption for digital sign
        if self.sign_value.get():
            try:
                self.infoBox.insert(END, "[I] Verifying signature ...\n")
                with open("./rsa/a_pubkey_rsa", mode='r+') as pubfile: # Alice Public key selected by default
                    keydata = pubfile.read()
                n_start = keydata.find("\n\n")+2
                n = int(keydata[n_start:keydata.find("-----RSA Public Key END-----")], 16)
                e = int(keydata[keydata.find("\n\n") -1:keydata.find("\n\n")], 16)
                with open("./signature", mode='r+') as signfile: # signature
                    signature_data = signfile.read()
                hash = int.from_bytes(sha512(plaintext[:32]).digest(), byteorder='big')
                hashFromSignature = pow(int(signature_data, 16), e, n)
                print("Signature valid:", hash == hashFromSignature)
                self.infoBox.insert(END, f"\n=> Signature valid: {hash == hashFromSignature}\n")
            except Exception as err:
                messagebox.showerror('Error', f'Error: To verify the signature x(\n{err}')
                self.infoBox.insert(END, f"[E] To verify the signature x(\n\n\t{err}")
        self.infoBox.insert(END, f"[I] Plaintext gotten: \n {plaintext}\n\n\n")
        
if __name__ == '__main__':
    print("\n\n**ETS Project**")
    init()
    windowLayout()
