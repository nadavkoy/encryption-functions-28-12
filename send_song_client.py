import socket
from AES import *
from KeyGenerator import *
import pickle
import os

KEY = os.urandom(16)


class Client(object):
    """ creating client """
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 4500))
        self.aes = AESCrypt()
        self.rsa = Cryptonew()
        self.public = ''

    def unpack(self, data):
        return pickle.loads(data.decode('base64'))

    def pack(self, data):
        return pickle.dumps(data).encode('base64')


def send_key(client):
    """ sends encryption key with the public key """
    client.public = client.client_socket.recv(1024)  # receiving public
    client.public = client.unpack(client.public)  # unpacking
    encrypted_key = client.rsa.encrypt(KEY, client.public)  # encrypting key with public
    client.client_socket.send(encrypted_key)  # sending key
    response = client.client_socket.recv(1024)  # receiving server's confirmation
    print response


def encrypt_request(client, request):
    """ encrypts client's request """
    return client.aes.encryptAES(KEY, request)


def decrypt_response(client, response):
    """ decrypts server's response """
    return client.aes.decryptAES(KEY, response)


def main():
    client = Client()
    send_key(client)
    while True:
        name = encrypt_request(client, raw_input())
        client.client_socket.send(name)
        response = client.client_socket.recv(1024)
        print decrypt_response(client, response)


if __name__ == '__main__':
    main()