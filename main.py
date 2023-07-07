from Crypto.Cipher import AES
import os
import rsa
import sys


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
    return {"ciphertext": outputfile, "tag": tag, "nonce": nonce}


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
        print(f"\t\t[I] -> {person} key files found, skipping creation...")
        return
    (pubkey, privkey) = rsa.newkeys(512)
    try:
        with open(f"./{person}/rsa/id_rsa", "wb+") as pubfile:
            pubfile.write(pubkey.save_pkcs1())
            print(f"{person} pubkey generated")
        with open(f"./{person}/rsa/id_rsa.pem", "wb+") as privfile:
            privfile.write(privkey.save_pkcs1())
    except FileExistsError:
        print("\t Something went really wrong! x(")
        pass
    print(f"{person} pubkey generated")


def getPubkeyFromPerson(person):
    with open(f"./{person}/rsa/id_rsa", mode='rb') as pubfile:
        keydata = pubfile.read()
        return rsa.PublicKey.load_pkcs1(keydata)


def getPrivateKeyFromPerson(person):
    with open(f"./{person}/rsa/id_rsa.pem", mode='rb') as privatefile:
        keydata = privatefile.read()
        return rsa.PrivateKey.load_pkcs1(keydata)


def sendAMessage(sender, receiver, file_name):
    if not os.path.exists(f'./{sender}/{file_name}'):
        print("\t[E] Message file does not exist :(")
        exit(1)
    with open(f'./{sender}/{file_name}', 'rb') as message_file:
        data = message_file.read()
    iv = getRandomBytes(16)
    print(f'The plain text is: "{data.decode()}"')
    # AES Ciphering
    parameters = AEScipher(data, iv, f"./{receiver}/ciphered_message.bin")
    # RSA parameter Ciphering
    # Set the parameters on a file
    with open(f"./{sender}/parameters.bin", "+wb") as parameters_file:
        for k in parameters:
            if isinstance(parameters[k], (bytes, bytearray)):
                parameters_file.write(
                    bytes(k, 'utf-8') + b':' + parameters[k] + b'\n')
                # print(bytes(k, 'utf-8') + b':' + parameters[k])
            else:
                parameters_file.write(
                    bytes(k, 'utf-8') + b':' + bytes(parameters[k], 'utf-8') + b'\n')
                # print(bytes(k, 'utf-8') + b':' + bytes(parameters[k], 'utf-8'))
        parameters_file.seek(0)  # return the cursor to the beginning
        parameters_data = parameters_file.read()
        # Cipher the parameters in a file and send it to the receiver
        print(f"\t[I] Ciphering parameters...")
        print(
            f"\t[I] => The file size is {len(parameters_data)} and max block size is 53")
        print(
            f"\t[I] => Total of blocks is: {round(len(parameters_data)/53)}")
        receiver_pubkey = getPubkeyFromPerson(receiver)
        with open(f"./{receiver}/ciphered_parameters.bin", "+wb") as ciphered_parameters_file:
            step = 0
            crypto = b''
            for i in range(0, len(parameters_data), 53):  # ciphering by 53-size blocks
                crypto = crypto + \
                    rsa.encrypt(parameters_data[i:52+i], receiver_pubkey)
                print(f"This is the block {step}: {parameters_data[i:52+i]}")
                step = step + 1
            # print("This is the whole message encrypted", crypto)
            ciphered_parameters_file.write(crypto)
        print("\t[I] Parameters Ciphered successfully!")
        print("Message sent!")
        print("////////////////////////////////////////")
        print("Let's do the verification...")
        with open(f"./{receiver}/rsa/id_rsa.pem", mode='rb') as privatefile:
            keydata = privatefile.read()
        privkey = rsa.PrivateKey.load_pkcs1(keydata)
        message = b''
        print(f"Length of crypto: {len(crypto)}")
        print("This is the whole message encrypted", crypto)
        # for i in range(step):
        #     print(f"Step {i}")
        #     message = message + rsa.decrypt(crypto[i:52+i], privkey)
        # print("This is the message", message)
    print("\n\n")


def receiveAMessage(person):
    # TODO:
    # Get the cipheredParameters file
    with open(f"./{person}/ciphered_parameters.bin") as cparameter_file:
        ciphered_parameters = cparameter_file.readlines()
        print(ciphered_parameters)
    # Obtain privKey
    with open(f"./{person}/rsa/id_rsa.pem", mode='rb') as privatefile:
        keydata = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    # Decrypt by 53-size blocks
    print(f"\t => Parameters size: {len(ciphered_parameters)}")
    parameters = rsa.decrypt(ciphered_parameters, privkey)
    print(f"We got this: {parameters}")
    # get the cipheredMessage file
    # decrypt with obtaned parameters

    # plaintext = AESdecipher(cdata["ciphertext"],
    #                         iv, cdata["tag"], cdata["nonce"])
    # print(f"\t This is the plainText: {plaintext.decode('UTF8', 'replace')}")
    return


if __name__ == '__main__':
    print("\n\n**ETS Project**")
    init()
    for i in sys.argv:
        if i == 'send':
            sendAMessage('Alice', 'Bert', 'testMessage.txt')
            exit(0)
        if i == 'receive':
            receiveAMessage('Bert')
            exit(0)
