import os
from Crypto.Cipher import AES
import rsa


def getRandomBytes(size):
    iv = os.urandom(size)
    print(f"\t[I] Taking random bytes...")
    # print(f"Random bytes are: {iv}")
    # Manually get random bytes from /dev/urandom
    # with open("/dev/random", 'rb') as f:
    # print repr(f.read(10))
    return iv


def AEScipher(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {"ciphertext": ciphertext, "tag": tag, "nonce": nonce}


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


def sendAMessage(sender, receiver, file_name):
    if not os.path.exists(f'./{sender}/{file_name}'):
        print("\t[E] Message file does not exist :(")
        exit(1)
    message_file = open(f'./{sender}/{file_name}', 'rb')
    data = message_file.read()
    iv = getRandomBytes(16)
    print(f'The plain text is: "{data.decode()}"')
    cdata = AEScipher(data, iv)
    ciphered_message_file = open(f"./{receiver}/ciphered_message.bin", "wb")
    ciphered_message_file.write(cdata['ciphertext'])
    cdata['ciphertext'] = f"./{receiver}/ciphered_message.bin"
    ciphered_message_file.close()
    message_file.close()


if __name__ == '__main__':
    print("**ETS Project**")
    init()
    sendAMessage('Alice', 'Bert', 'testMessage.txt')
    # plaintext = AESdecipher(cdata["ciphertext"],
    #                         iv, cdata["tag"], cdata["nonce"])
    # print(f"\t This is the plainText: {plaintext.decode('UTF8', 'replace')}")
