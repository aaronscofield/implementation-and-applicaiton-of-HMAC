import hmac
from des import DesKey
import random
import re
import socket
import string


# function connectToServer() creates a socket variable, sets the port, and connects to the localhost.
def connectToServer():
    global s
    s = socket.socket()
    port = 12345
    s.connect(('127.0.0.1', port))


# function genDESKey() creates a .txt file named DESkey.txt, generates a random string of 8 letters and closes the file.
def genDESKey():
    f = open("DESkey.txt", "w")
    letters = string.ascii_letters
    f.write(''.join(random.choice(letters) for _ in range(8)))
    f.close()


# function genHMACKey() creates a .txt file named HMACkey.txt, generates a random shared hmac key
# consisting of 32 letters.
def genHMACKey():
    f = open("HMACKey.txt", "w")
    letters = string.ascii_letters
    f.write(''.join(random.choice(letters) for _ in range(32)))
    f.close()


# function genHash() hashes the input message with the key from file. it uses the MD5 hash.
def genHash(message_to_hash):
    f2 = open("HMACkey.txt", "r")
    hmac_key_from_file = f2.read()

    hmac_key_bytes_from_file = bytes(hmac_key_from_file, 'latin-1')
    message_to_hash_bytes = bytes(message_to_hash, 'latin-1')

    digest_maker = hmac.new(hmac_key_bytes_from_file, message_to_hash_bytes, digestmod='MD5')
    hashed_message = str(digest_maker.digest())
    return hashed_message


# function welcomeMessage() opens and reads in the DES and HMAC keys and prints them in addition to the inputted user
# message and the hashed user message to the console
def welcomeMessage():
    f = open("DESkey.txt", "r")
    deskey = f.read()

    f2 = open("HMACKey.txt", "r")
    hmackey = f2.read()

    print("Hi, this is client.")
    print("Shared DES Key is: " + deskey)
    print("Shared HMAC Key is: " + hmackey)
    print("message to encrypt: " + client_message)
    print("sender side HMAC: " + hashed_client_message)


# function genAndSendCipherText() reads the key from the text file, converts it to bytes, and encrypts the
# message via DES. the encrypted ciphertext is sent to the server and outputted to the console.
def genAndSendCipherText():
    # open read, and encode key, set to key0
    f = open("DESkey.txt", "r")
    key_from_file = str.encode(f.read())
    key0 = DesKey(key_from_file)

    # encrypt plaintext and send to server
    encrypted_message = key0.encrypt(combo_message, padding=True)
    s.send(encrypted_message)

    # print ciphertext to console
    print("sent ciphertext:", end=' ')
    print(encrypted_message)
    print("************************************************")


# function receiveResponse() listens on the port for a response from the server. the function accepts the response,
# and outputs the ciphertext to the console. It then uses regex to separate the message and the hashed message,
# calculates the HMAC of the message using the secret key, and compares that to the HMAC received. If there is a match,
# it outputs to the console that the hmac has been verified.
def receiveResponse():
    ciphertext_received = s.recv(1024)
    if ciphertext_received != "":
        print("Ciphertext received from server:", end=' ')
        print(ciphertext_received)

        f = open("DESkey.txt", "r")
        des_key_from_file = str.encode(f.read())
        des_key0 = DesKey(des_key_from_file)
        decrypted_text = des_key0.decrypt(ciphertext_received, padding=True)

        # use regex to pull message from the decrypted text received
        pattern = "b\"(.*?)b'"
        substring = re.search(pattern, str(decrypted_text)).group(1)
        print("received message: " + substring)

        # use regex to pull received hmac from the decrypted text received, remove duplicate backslashes
        pattern2 = "b\"" + substring + "(.*?)" + "\""
        substring2 = re.search(pattern2, str(decrypted_text)).group(1)
        substring2 = substring2.replace('\\\\', '\\')
        print("received hmac: " + substring2)

        # calculate own HMAC with the message and shared secret HMAC key
        f2 = open("HMACKey.txt", "r")
        hmac_key_from_file = f2.read()
        hmac_key_bytes_from_file = bytes(hmac_key_from_file, 'latin-1')
        substring_bytes = bytes(substring, 'latin-1')

        digest_maker = hmac.new(hmac_key_bytes_from_file, substring_bytes, digestmod='MD5')
        hashed_message = str(digest_maker.digest())
        print("calculated hmac: " + hashed_message)

        # verify the generated hmac and the received hmac
        if substring2.find(hashed_message) != -1:
            print("HMAC VERIFIED")
        else:
            print("HMAC NOT VERIFIED")

        print("************************************************")


# the main function calls the other functions and accepts the input message to be encrypted
if __name__ == "__main__":
    genDESKey()
    genHMACKey()
    connectToServer()

    client_message = input("Enter your message to encrypt: ")
    client_message_as_bytes = bytes(client_message, 'latin-1')
    hashed_client_message = genHash(client_message)
    hashed_client_message_as_bytes = bytes(hashed_client_message, 'latin-1')

    combo_message = client_message_as_bytes + hashed_client_message_as_bytes

    welcomeMessage()
    genAndSendCipherText()
    receiveResponse()
