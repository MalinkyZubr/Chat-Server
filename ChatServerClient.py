import socket
from threading import Thread, Lock
from json import loads, dumps
import json
import re
import os
import time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto import Random
import numba
from numba import jit
import dask
import random
from base64 import b64decode, b64encode
import hashlib


class SocketOpts:
    def pack_and_send(self, message, connection=None):
        json_message = dumps(message)
        connection.send(json_message.encode('utf-8'))

    def full_receive(self, connection=None):
        message = ""
        while True:
            try:
                message = message + \
                    loads(connection.recv(1024).decode('utf-8'))
                return message
            except ValueError:
                continue


class AESCipher(object):
    def __init__(self):
        self.block_size = AES.block_size

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - \
            len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]

    def encrypt(self, plain_text, key):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode('utf-8')

    def decrypt(self, encrypted_text, key):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text)
        return self.__unpad(plain_text)


class SocketSecurity:
    def __init__(self):
        self.socket_opts = SocketOpts()
        self.aes_cipher = AESCipher()
        self.session_key_unhashed = random.randint(1000000000000000000000000000000000000000000000000000000,
                                                   1100000000000000000000000000000000000000000000000000000)
        self.session_key = self.hasher(b64encode(self.session_key_unhashed))

    def hasher(self, input_num):
        hash_iteration = hashlib.sha512(input_num).hexdigest().encode()
        for x in range(int(b64decode(input_num)[:4])):
            hash_iteration = hashlib.sha512(
                hash_iteration).hexdigest().encode()
        return hash_iteration.decode('utf-8')

    def key_exchange(self, connection=None):
        public_1, public_2 = self.socket_opts.full_receive(
            connection=connection)
        response_key = ((self.session_key_unhashed ** public_2) % public_1)
        self.socket_opts.pack_and_send(response_key, connection=connection)

    def encrypted_send(self, connection=None, key=None, message=None):
        encrypted_message = self.aes_cipher.encrypt(message, key)
        self.socket_opts.pack_and_send(
            encrypted_message, connection=connection)

    def receive_and_decrypt(self, connection=None, key=None):
        encrypted_message = self.socket_opts.full_receive(
            connection=connection)
        decrypted_message = self.aes_cipher.decrypt(encrypted_message, key)
        return decrypted_message


class Commands:
    def __init__(self):
        self.command_list = {
            "help": "display all commands",
            "disconnect": "disconnect from the server",
            "display_connections": "display all connected clients",
        }

    def command_list_display(self, command_list):
        print("###COMMAND LIST###\n")
        for name, description in command_list.items():
            print(f"	{name}: {description}")

    def disconnect(self):
        print("[+]Disconnected from the server")
        self.connection.close()
        os._exit(1)

    def execute_command(self, command):
        command_list = self.command_list
        if command[0].lower() == "&&help":
            self.command_list_display(command_list)

        if command[0].lower() == "&&disconnect":
            self.disconnect()


class Client:
    def __init__(self, ip, port, displayname="Guest"):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))
        self.mqueue = []
        self.name = displayname
        self.socket_opts = SocketOpts()
        self.commands = Commands()
        self.mqueuelock = Lock()

    def send_messages(self, name):
        print("[+]Ready to send messages!")
        while True:
            try:
                message = str(input(""))
                if message[0:2] != "&&":
                    formatted_message = f"{datetime.now().strftime('%H:%M:%S')}--{name}: {message}"
                    self.socket_opts.pack_and_send(
                        formatted_message, connection=self.connection)
                else:
                    self.commands.execute_command(message.split(" "))
            except OSError:
                continue
            except ConnectionResetError:
                print("[-] Connection was Lost")
                os._exit(1)

    def receive_message(self):
        print("[+]Ready to receive messages!")
        while True:
            try:
                message = self.socket_opts.full_receive(
                    connection=self.connection)
                with self.mqueuelock:
                    self.mqueue.append(message)
            except ConnectionResetError:
                print("[-] Connection was Lost")
                os._exit(1)
            # except OSError:
                # continue

    def print_messages(self, name):
        while True:
            with self.mqueuelock:
                while self.mqueue:
                    for message in self.mqueue:
                        if message[0:2] and message[-2:] != "&&" and f"{name}" not in message[:20]:
                            print(message)
                            self.mqueue.remove(message)
                        elif message == "&&SERVER SHUTDOWN INITIATED&&":
                            print("[!] Server shutdown was initiated!")
                            os._exit(1)
                        elif message == "&&KICKED&&":
                            os._exit(1)
                        else:
                            self.mqueue.pop(0)

    def main(self):
        sender = Thread(target=self.send_messages, args=[self.name])
        receiver = Thread(target=self.receive_message)
        printer = Thread(target=self.print_messages, args=[self.name])

        thread_list = [sender, receiver, printer]

        for thread in thread_list:
            thread.start()


if __name__ == '__main__':
    while True:
        name = str(input("Enter your display name here >>"))
        if len(name) >= 20:
            print("Please enter a name under 20 characters long")
        else:
            break

    client = Client("72.194.82.31", 2222, displayname=name)
    client.main()
