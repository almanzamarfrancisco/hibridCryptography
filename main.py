import os
from Crypto.Cipher import AES


def getRandomBytes(size):
    iv = os.urandom(size)
    print(f"Taking")
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


if __name__ == '__main__':
    print("**Just AES**")
    iv = getRandomBytes(16)
    data = b'Testing Text'
    print(f'The plain text is: "{data.decode()}"')
    cdata = AEScipher(data, iv)
    plaintext = AESdecipher(cdata["ciphertext"],
                            iv, cdata["tag"], cdata["nonce"])
    print(f"\t This is the plainText: {plaintext.decode('UTF8', 'replace')}")
