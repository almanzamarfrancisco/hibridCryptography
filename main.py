from Crypto.Cipher import AES
from functools import partial
from tkinter import ttk
from tkinter import *
import sys
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
    return {"ciphertext": outputfile, "nonce": nonce, "tag": tag, "iv": key}


def AESdecipher(ciphertext, key, tag, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("\t[I] The message is authentic! :)")
    except ValueError:
        print("\t[E] Key incorrect or message corrupted :(")
    return plaintext


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
    print(f"\t-> Lenght: {len(parameters)} \n\t-> Parameters: {parameters}")
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


def sendAMessage(sender, receiver, file_name):
    if not os.path.exists(f'./{sender}/{file_name}'):
        print("\t[E] Message file does not exist :(")
        exit(1)
    with open(f'./{sender}/{file_name}', 'rb') as message_file:
        data = message_file.read()
    iv = getRandomBytes(16)
    # print(f'The plain text is: "{data.decode()}"')
    # AES Ciphering
    parameters = AEScipher(data, iv, f"./{receiver}/ciphered_message")
    # RSA parameter Ciphering
    # Set the parameters on a file
    parameters_bytes = b''
    with open(f"./{sender}/parameters", "+wb") as parameters_file:
        for k in parameters:
            try:
                # print(bytes(k, 'utf-8') + b':' + bytes(parameters[k], 'utf-8')+b'^')
                parameters_bytes = parameters_bytes + \
                    bytes(k, 'utf-8') + b':' + \
                    bytes(parameters[k], 'utf-8')+b'^'
            except TypeError:
                # print(bytes(k, 'utf-8') + b':' + parameters[k] + b'^')
                parameters_bytes = parameters_bytes + \
                    bytes(k, 'utf-8') + b':' + parameters[k] + b'^'
        parameters_file.write(parameters_bytes)
        parameters_file.seek(0)  # return the cursor to the beginning
        parameters_data = parameters_file.read()
        # print(f"\t\t => Parameters data: {parameters_data}")
        # Cipher the parameters in a file and send it to the receiver
        print(f"\t[I] Ciphering parameters...")
        print(
            f"\t\t=> The file size is {len(parameters_data)} and max block size is 53")
        print(
            f"\t\t=> Total of blocks is: {round(len(parameters_data)/53)}")
        receiver_pubkey = getPubkeyFromPerson(receiver)
        with open(f"./{receiver}/ciphered_parameters", "+wb") as ciphered_parameters_file:
            crypto = b''
            for i in range(0, len(parameters_data), 54):  # ciphering by 53bytes-size blocks
                if i == 0:
                    # print(
                    #     f"from {i} to {i+53} len: {len(parameters_data[i:53+i])} => {parameters_data[i:53+i]}")
                    crypto = crypto + \
                        rsa.encrypt(parameters_data[i:53+i], receiver_pubkey)
                else:
                    # print(
                    #     f"from {i} to {i+53} len: {len(parameters_data[i-1:53+i])} => {parameters_data[i-1:53+i]}")
                    crypto = crypto + \
                        rsa.encrypt(parameters_data[i-1:53+i], receiver_pubkey)
            # print(
            #     f"This is the whole message encrypted ({len(crypto)}): {crypto}")
            ciphered_parameters_file.write(crypto)
        print("\t[I] Parameters Ciphered successfully!")
        print("====================================================================")
        print("=> Let's test thins thing!: ")
        with open(f"./{receiver}/ciphered_parameters", "rb+") as testfile:
            testcdata = testfile.read()
            testdata = rsaDecryptParameterBytes(
                testcdata, getPrivateKeyFromPerson('Bert'))
        print(f"\n\n")
        print(f"=> original  ({len(parameters_data)}): {parameters_data}")
        print(f"=> deciphered({len(testdata)}): {testdata}")
        print(f"\n\n")
        dec_params = getListFromBytes(testdata)
        param_list = getListFromBytes(parameters_data)
        print(f"=> original  : {param_list}")
        print(f"=> deciphered: {dec_params}")
        print(f"////////////////////////////")
        with open(param_list[0]['ciphertext'], 'rb') as ciphertextfile:
            cipheredText = ciphertextfile.read()
        AESdecipher(
            cipheredText, param_list[3]['iv'], param_list[2]['tag'], param_list[1]['nonce'])
        print(f"////////////////////////////")
        with open(dec_params[0]['ciphertext'], 'rb') as ctf:
            ct = ctf.read()
        AESdecipher(ct, dec_params[3]['iv'],
                    dec_params[2]['tag'], dec_params[1]['nonce'])
        print("====================================================================")
        print("=> Message sent!")


def receiveAMessage(person):
    # Get the cipheredParameters file
    try:
        with open(f"./{person}/ciphered_parameters", mode="rb") as cparameter_file:
            ciphered_parameters = cparameter_file.read()
    except FileNotFoundError:
        print("Wait! there is no message to receive x(")
        exit(1)
    # Obtain person privKey
    with open(f"./{person}/rsa/id_rsa.pem", mode='rb') as privatefile:
        keydata = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    # Decrypt by 64bytes-size blocks
    parameters_in_bytes = rsaDecryptParameterBytes(
        ciphered_parameters, privkey)
    parameters = getListFromBytes(parameters_in_bytes)
    # Get the cipheredMessage file
    with open(f"./{person}/ciphered_message", mode="rb") as cmessage_file:
        ciphered_message = cmessage_file.read()
    # Decrypt with obtaned parameters
    message = AESdecipher(ciphered_message, parameters[3]['iv'],
                          parameters[2]['tag'], parameters[1]['nonce'])
    print(f"=====> This is the message: \n{message.decode()}")
    return


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


if __name__ == '__main__':
    print("\n\n**ETS Project**")
    init()
    for i in sys.argv:
        if i == 'send':
            sendAMessage('Alice', 'Bert', 'testMessage.txt')
            print("\n\n")
            exit(0)
        if i == 'receive':
            receiveAMessage('Bert')
            print("\n\n")
            exit(0)
    # windowLayout()
