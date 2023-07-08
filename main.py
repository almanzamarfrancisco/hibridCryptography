from Crypto.Cipher import AES
import os
import rsa
import sys
import json


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
    return {"ciphertext": outputfile, "tag": tag, "nonce": nonce, "iv": key}


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


def getParametersArray(ciphered_parameters, privkey):
    parameters = b''
    for i in range(0, len(ciphered_parameters), 64):
        parameters = parameters + \
            rsa.decrypt(ciphered_parameters[i:64+i], privkey)
    # print(f"\t-> Lenght: {len(parameters)} \n\t-> Parameters: {parameters}")
    parameter_value_ending = 0
    parameter_key_ending = 0
    parameters_list = []
    keys_found = 0
    key_found = ''
    value_found = ''
    for i, c in enumerate(parameters):
        if not chr(c).isprintable():
            if chr(parameters[i]).encode('unicode_escape').decode() == '\\n':
                parameter_value_ending = i
                try:
                    value_found = parameters[parameter_key_ending+1:parameter_value_ending].decode(
                    )
                except UnicodeDecodeError:
                    value_found = parameters[parameter_key_ending +
                                             1:parameter_value_ending]

                # print(
                #     f"\t\t-> After of finding value: {value_found}")
                # print(f"\t\t-> Keys found: {keys_found}")
                parameters_list[keys_found - 1][key_found] = value_found
                parameter_key_ending = i + 1
        else:
            if chr(c) == ':':
                key_found = parameters[parameter_key_ending:i].decode()
                # print(
                #     f"\t-> Value found: {key_found}")
                parameters_list.append(
                    {key_found: ''})
                parameter_key_ending = i
                keys_found = keys_found + 1
    # print(f"\t[I] Parameters list:")
    # for p in parameters_list:
    #     print(f"\t\t => {p}")
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
    with open(f"./{sender}/parameters", "+wb") as parameters_file:
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
        # print(parameters_data)
        # Cipher the parameters in a file and send it to the receiver
        print(f"\t[I] Ciphering parameters...")
        print(
            f"\t\t => The file size is {len(parameters_data)} and max block size is 53")
        print(
            f"\t\t => Total of blocks is: {round(len(parameters_data)/53)}")
        receiver_pubkey = getPubkeyFromPerson(receiver)
        with open(f"./{receiver}/ciphered_parameters", "+wb") as ciphered_parameters_file:
            crypto = b''
            for i in range(0, len(parameters_data), 53):  # ciphering by 53bytes-size blocks
                crypto = crypto + \
                    rsa.encrypt(parameters_data[i:52+i], receiver_pubkey)
            # print("This is the whole message encrypted", crypto)
            ciphered_parameters_file.write(crypto)
        print("\t[I] Parameters Ciphered successfully!")
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
    parameters = getParametersArray(ciphered_parameters, privkey)
    # Get the cipheredMessage file
    with open(f"./{person}/ciphered_message", mode="rb") as cmessage_file:
        ciphered_message = cmessage_file.read()
    # Decrypt with obtaned parameters
    message = AESdecipher(ciphered_message, parameters[3]['iv'],
                          parameters[1]['tag'], parameters[2]['nonce'])
    print(f"=====> This is the message: \n{message.decode()}")
    return


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
