import socket
import hmac
from des import DesKey
import re

# create socket, set port number, bind socket to port number
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 12345
s.bind(('', port))

# open socket for listening
s.listen(5)
print("Socket is now listening...")

# accept incoming socket connections
c, addr = s.accept()
print("Accepted connection from ", addr)
print("Hi, this is server.")

# main while loop, receives and interprets input from client, then sends response.
while True:
    ciphertext_received = c.recv(1024)
    if ciphertext_received != "":
        print("Ciphertext received from client:", end=' ')
        print(ciphertext_received)

        # open deskey.txt and store the key as des_key0. the ciphertext is then decrypted with the key.
        f = open("DESkey.txt", "r")
        DESkey_from_file = str.encode(f.read())
        DESkey0 = DesKey(DESkey_from_file)
        decryptedText = DESkey0.decrypt(ciphertext_received, padding=True)

        # use regex to pull message from the decrypted text received
        pattern = "b\"(.*?)b'"
        substring = re.search(pattern, str(decryptedText)).group(1)
        print("received message: " + substring)

        # use regex to pull received hmac from the decrypted text received, remove duplicate backslashes
        pattern2 = "b\"" + substring + "(.*?)" + "\""
        substring2 = re.search(pattern2, str(decryptedText)).group(1)
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

        # prompt the user to enter a response, convert it to bytes
        response = input("Enter a response to send to the client: ")
        response_as_bytes = bytes(response, 'latin-1')

        # hash the response with the hmac key from file
        digest_maker = hmac.new(hmac_key_bytes_from_file, response_as_bytes, digestmod='MD5')
        hashed_message = str(digest_maker.digest())
        hashed_message_as_bytes = bytes(hashed_message, 'latin-1')

        combo_message = response_as_bytes + hashed_message_as_bytes

        encryptedResponse = DESkey0.encrypt(combo_message, padding=True)
        c.send(encryptedResponse)

        # print key, plaintext, and encrypted ciphertext to console
        print("Shared DES key is: " + str(DESkey_from_file))
        print("Shared HMAC key is: " + hmac_key_from_file)
        print("Message to encrypt: " + response)
        print("Sender side HMAC: " + hashed_message)
        print("Send ciphertext: " + str(encryptedResponse))
        print("************************************************")

        break
