import threading
import socket
from AES import *
from KeyGenerator import *


class Server(object):
    def __init__(self):
        self.server_socket = socket.socket()
        self.server_socket.bind(('0.0.0.0', 4500))
        self.server_socket.listen(10)

        # for encryption:
        self.rsa = Cryptonew()  # creating a new Cryptonew object to encrypt and decrypt with RSA
        self.public_key = self.rsa.get_public()  # getting the public RSA key
        self.private_key = self.rsa.get_private()  # getting the private RSA key

    def accept(self):
        return self.server_socket.accept()


class ClientHandler(threading.Thread):
    def __init__(self, address, socket, public_key, private_key, rsa):
        super(ClientHandler, self).__init__()
        self.sock = socket
        self.address = address

        # for encryption:
        self.rsa = rsa  # rsa is a Cryptonew object that we got from server as a parameter
        self.key = ''  # this variable will hold the AES that we'll get from the client
        self.public = public_key  # the public key we got from the server as a parameter
        self.private = private_key  # the private key we got from the server as a parameter
        self.aes = AESCrypt()  # creating a AESCrypt object to encrypt and decrypt with AES.

    def get_client_key(self):
        """ decoding the encryption key """
        self.sock.send(self.rsa.pack(self.public))  # sending the pickled public key to the client
        encrypted_key = self.sock.recv(1024)  # getting the AES key encrypted with the public key
        self.key = self.rsa.decode(encrypted_key, self.private)  # decoding the encrypted key with the private key
        self.sock.send('got the key!')  # sends a message to the client to approve that received

    def decrypt_message(self, encrypted_client_request):
        """ decrypts the client's request """
        return self.aes.decryptAES(self.key, encrypted_client_request)  # decrypt the message with AES key

    def encrypt_message(self, response):
        """ encrypts the server's response """
        return self.aes.encryptAES(self.key, response)  # encrypt the message with AES key

    def run(self):
        self.get_client_key()
        while True:
            client_request = self.sock.recv(1024)
            client_decrypted_request = self.decrypt_message(client_request)
            response = 'hello, ' + client_decrypted_request
            self.sock.send(self.encrypt_message(response))


def main():
    server = Server()
    while True:
        socket, address = server.accept()
        client_hand = ClientHandler(address, socket, server.public_key, server.private_key, server.rsa)
        client_hand.start()


if __name__ == '__main__':
    main()

