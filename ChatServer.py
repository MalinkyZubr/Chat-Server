import json
import os
import re
import socket
import sys
import threading
import time
from threading import Thread, Lock
from Crypto.Cipher import AES
from Crypto import Random
import random
import hashlib
from base64 import b64encode, b64decode
import time
import dask
import numba
from numba import jit
from numpy import int64
import system_logger

# ALSO, ADD SOME ENCRYPTION


class SocketOpts:
    def ip_identifier(self, connection):
        ip = list(re.findall(
            r"(?<=raddr=\(').*(?=')", str(connection)))
        return ip[0]

    def packager(self, data):
        return json.dumps(data).encode('utf-8')

    def pack_and_send(self, connection, data):
        json_package = json.dumps(data)
        connection.send(json_package.encode('utf-8'))

    def receive_and_unpack(self, connection):
        json_package = ""
        while True:
            try:
                json_package = json_package + \
                    connection.recv(32768).decode('utf-8')
                return json.loads(json_package)
            except ValueError:
                continue

    def cancel_connection(self, connection, connections=None):
        ip = self.ip_identifier(connection[0])
        connection[0].close()
        connections.remove(connection)
        connection[1].join()
        return f"[+]{ip} disconnected"


class PrimalityFinder:
    def second_test(self,num):
        if not num % 2 or not num % 3:
            return False
        else:
            return True

    def third_test(self,num):
        i = 0
        stop = int(num**0.5)
        while i <= stop:
            
            if not num % i or not num % (i+2):
                return False
            i += 6
        return True

    def primality(self):
        prime_list = []
        for num in range(100000000000000000000000000000000000000000000000,
                        100000000000000000000000000000000000000000100000):
            second = self.second_test(num)
            third = self.third_test(num)
            if second and third:
                prime_list.append(num)
            else:
                continue
        return prime_list

    def get_prime_pair(self, prime_list):
        index1 = int(random.randint(0, len(prime_list)))
        if index1 < 6:
            index2 = index1 + 6
        else:
            index2 = index1 - 3

        return prime_list[index1], prime_list[index2]


class PhiFinder:
    def gcd(self, p, q):
        while q != 0:
            p, q = q, p % q
        return p

    def is_coprime(self, x, y):
        return self.gcd(x, y) == 1

    def phi(self, x):
        if x == 1:
            return 1
        else:
            n = [y for y in range(1, x) if self.is_coprime(x, y)]
            return len(n)


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
        plain_text = cipher.decrypt(
            encrypted_text[self.block_size:]).decode('utf-8')
        return self.__unpad(plain_text)


class SocketSecurity:  # see khan academy to figure out how this RSA thing works, I dont remember
    def __init__(self):
        primality_finder = PrimalityFinder()
        phi_finder = PhiFinder()
        primes_list = primality_finder.primality()
        self.socket_opts = SocketOpts()
        self.aes_cipher = AESCipher()
        self.p1, self.p2 = primality_finder.get_prime_pair(primes_list)
        self.public_1 = (int(self.p1) * int(self.p2))
        self.phi_of_key = phi_finder.phi(self.public_1)
        self.public_2 = self.eligible_public_2(self.phi_of_key)
        self.private_key = (2 * self.phi_of_key + 1) / self.public_2
        self.public_key = (self.public_1, self.public_2)  # send this
        with open(r"server_certificate.pem", r) as cert:
            self.certificate = cert

    @staticmethod
    @jit(nopython=True, parallel=True, nogil=True)
    def get_factors(number):
        factors = []
        for i in numba.prange(1, number + 1):
            if number % i == 0:
                factors.append(i)

        return factors

    def is_odd(self, number):
        if number % 2 == 0:
            return False
        else:
            return True

    @staticmethod
    @jit(nopython=True)
    def list_similarity_checker(list1, list2):
        for number in list1:
            if number in list2:
                return True
            else:
                return False

    @staticmethod
    @jit(nopython=True)
    def eligible_public_2(phi):
        possible_public_2s = [
            number for number in numba.prange(85, 115)
            if is_odd(number) and not
            list_similarity_checker(get_factors(number), get_factors(phi))
        ]
        index = int(random.randint(0, len(possible_public_2s)))
        return possible_public_2s[index]

    def hasher(self, input_num):
        hash_iteration = hashlib.sha512(input_num).hexdigest().encode()
        for x in range(int(b64decode(input_num)[:4])):
            hash_iteration = hashlib.sha512(
                hash_iteration).hexdigest().encode()
        return hash_iteration.decode('utf-8')

    def key_exchange(self, connection):
        self.socket_opts.pack_and_send(connection, self.public_key)
        encryption_key_encrypted = self.socket_opts.receive_and_unpack(
            connection)
        encryption_key = b64encode
        (
            ((encryption_key_encrypted ** self.private_key) % self.public_1)
        )
        hashed_encryption_key = self.hasher(encryption_key)
        return hashed_encryption_key

    def encrypted_send(self, connection=None, key=None, message=None):
        encrypted_message = self.aes_cipher.encrypt(message, key)
        self.socket_opts.pack_and_send(connection, encrypted_message)

    def receive_and_decrypt(self, connection=None, key=None):
        encrypted_message = self.socket_opts.receive_and_unpack(connection)
        decrypted_message = self.aes_cipher.decrypt(encrypted_message, key)
        return decrypted_message


class SERVER_COMMANDS:
    def __init__(self):
        self.command_instructions = {
            "connections": "see list of active connections",
            "kick (ip_address, reason)": "force disconnect of connection at selected IP",
            "ban (ip_address, reason)": "adds ip address to ban_list file and prevents future logon",
            "unban (ip)": "Unbans a given IP",
            "servermessage": "Send a server-wide message",
            "shutdown": "Close the server and disconnect all clients"}
        self.SOCKET_OPTS = SocketOpts()

    def command_input(self, inputs):
        request = inputs.split(sep=" ")
        request = list(map(lambda y: y.lower(), request))
        command = request[0]
        argument_1 = request[1]
        return command, argument_1

    def kick_user(self, ip_requested=None, connections=None, reason=None):
        for connection, thread in connections:
            #ip = self.SOCKET_OPTS.ip_identifier(connection)
            if ip_requested in connection:
                self.SOCKET_OPTS.pack_and_send(
                    connection, f"[-]You have been kicked by the server admin. Reason: {reason}")
                self.SOCKET_OPTS.cancel_connection(
                    (connection, thread), connections=connections)
                return f"[!]User {ip} Was Kicked By Admin"
            else:
                return f"[-]User with ip {ip_requested} not found"

    def ban_user(self, ip_requested=None, connections=None, reason=None):
        for connection, thread in connections:
            #ip = self.ip_identifier(connection)
            if ip_requested in ip:
                self.SOCKET_OPTS.pack_and_send(
                    connection, f"[-]You have been BANNED by the server admin. Reason: {reason}")
                try:
                    self.SOCKET_OPTS.cancel_connection(
                        (connection, thread), connections)
                except (ConnectionAbortedError, ConnectionError):
                    pass
                with open(r'ban_list.txt', 'a') as ban_list:
                    ban_list.write(ip_requested)
                return f"[!]User {ip} Was BANNED By Admin"
            else:
                return f"[-]User with ip {ip_requested} not found"

    def unban_user(self, ip_requested=None):
        if ip_requested:
            with open(r"ban_list.txt", "w+") as ban_list:
                for line in ban_list.readlines():
                    if line == ip_requested:
                        ban_list.seek(0, 1)
                        ban_list.write('' * len(line))
                        return f"[!] IP {ip_requested} was unbanned"
                    else:
                        continue
        else:
            return "[!] No IP was given!"

    def display_connections(self, connections=None):
        print("###CONNECTIONS LIST###")
        connection_list = str()
        if connections:
            for connection, thread in connections:
                ip = self.SOCKET_OPTS.ip_identifier(connection)
                connection += f"\t{ip} Online\n"
            return connection
        else:
            return "[-]Connection List is Empty"

    def server_message(self, message_input=None):
        return self.SOCKET_OPTS.packager(f"## [!]SERVER-WIDE MESSAGE: {message_input} ##")

    def shutdown(self, connections=None):
        while connections:
            for connection, thread in self.connections:
                self.SOCKET_OPTS.pack_and_send(
                    connection, "&&SERVER SHUTDOWN INITIATED&&")
                self.SOCKET_OPTS.cancel_connection(
                    (connection, thread), connections)

        return ("[+]All connection successfully killed, server shutting down")
        os._exit(1)  # make this after function call

    def display_commands(self, commandlist):
        print("###COMMAND LIST###")
        command_list = str()
        for command, description in commandlist.items():
            command_list += f"-----{command}: {description}\n"
        return command_list


class Server:
    def __init__(self, IP, PORT):
        self.IP = IP
        self.PORT = PORT
        self.connections = []
        self.message_queue = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.IP, self.PORT))
        self.sock.listen(10)

        self.SOCKET_OPTS = SocketOpts()
        self.SERVER_COMMANDS = SERVER_COMMANDS()
        self.SOCKET_SECURITY = SocketSecurity()

        self.connections_lock = Lock()
        self.message_lock = Lock()

        self.system_logger = system_logger.getLogger('System Log')
        self.system_logger.setLevel(system_logger.DEBUG)
        stream_hanlder = self.system_logger.StreamHandler()
        file_handler = self.system_logger.FileHandler(r'system_logs.txt')
        stream_hanlder.setLevel(DEBUG)
        file_handler.setLevel(INFO)
        log_format = self.system_logger.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(messages)s")
        stream_hanlder.setFormatter(log_format)
        file_handler.setFormatter(log_format)
        self.system_logger.addHandler(stream_handler)
        self.system_logger.addHandler(file_handler)

        self.message_logger = system_logger.getLogger('Message Log')
        self.message_logger.setLevel(system_logger.INFO)
        message_file_handler = self.message_logger.FileHandler(r'message_logs')
        message_file_handler.setLevel(INFO)
        message_log_format = self.message_logger.Formatter("%(name)s - %(message)s")
        message_file_handler.setFormatter(message_log_format)
        self.message_logger.addHandler(message_file_handler)

    def ping(self):
        self.system_logger.info("[+]Pinging All Connections")
        while True:
            # self.system_logger.info(self.connections)
            time.sleep(2)
            with self.connections_lock:
                for connection, thread in self.connections:
                    if not thread.is_alive():
                        self.system_logger.info(self.SOCKET_OPTS.cancel_connection(
                            (connection, thread), connections=self.connections))
                        break
                    try:
                        self.SOCKET_OPTS.pack_and_send(
                            connection, "&&ACTIVE?&&")
                    except ConnectionAbortedError:
                        self.system_logger.info(self.SOCKET_OPTS.cancel_connection(
                            (connection, thread), connections=self.connections))

    def transmit(self):
        self.system_logger.info("[+]Ready To Send Messages")
        while True:
            with self.connections_lock, self.message_lock:
                if self.message_queue and self.connections:
                    for connection, thread in self.connections:
                        try:
                            connection.send(self.message_queue[0])
                        except (RuntimeError,
                                ConnectionAbortedError,
                                IndexError,
                                ConnectionResetError
                                ):
                            continue
                        if len(self.message_queue) > 100:
                            self.message_queue.clear()
                    try:
                        self.message_queue.pop(0)
                    except IndexError:
                        continue

    def receive(self, connection):
        # i dont know why this needs to be a tuple but the code doesnt work without it
        connection = tuple(connection)
        ip = self.SOCKET_OPTS.ip_identifier(connection[0])
        message_count = 0
        while connection in self.connections:
            start_time = time.time()
            end_time = start_time + 5
            while time.time() < end_time and message_count <= 4:
                try:
                    message = connection[0].recv(32768)
                except (ConnectionAbortedError, ConnectionResetError):
                    sys.exit(1)
                if message:
                    with self.message_lock:
                        self.message_queue.append(message)
                    self.message_logger.info(f"{ip}--{message}")
                    message_count += 1
                    self.system_logger.info(message_count)
            if message_count >= 4:
                self.SOCKET_OPTS.pack_and_send(
                    connection[0], "[-]You were kicked for spamming")
                with self.message_lock:
                    self.message_queue.append(
                        self.SERVER_COMMANDS.server_message("Please no spamming :)"))
                sys.exit(1)
            else:
                message_count = 0
                continue

    def take_requests(self):  # add here an encryption key exchange
        self.system_logger.info("[+]Ready For Connections")
        logon_message = "[+]Connection Established"
        rejected_message = "[-]Connection rejected. Banned"
        while True:
            new_connection = self.sock.accept()[0]
            ip = self.SOCKET_OPTS.ip_identifier(new_connection)
            full_connection = [new_connection, True]
            full_connection[1] = Thread(
                target=self.receive, args=(full_connection,))
            full_connection = tuple(full_connection)
            with self.connections_lock:
                self.connections.append(full_connection)
                full_connection[1].start()
                with open(r'ban_list.txt', 'r') as ban_list:
                    banned = ban_list.read()
                if ip not in banned:
                    self.SOCKET_OPTS.pack_and_send(
                        new_connection, logon_message)
                    self.system_logger.info(f"[+]{ip} connected to server")
                else:
                    self.pack_and_send(new_connection, rejected_message)
                    time.sleep(0.1)
                    self.SOCKET_OPTS.cancel_connection(
                        (new_connection, full_connection[1]), connections=self.connections)
                    self.system_logger.info(f"[+]{ip} was rejected from the server")

    def command_interface(self):
        self.system_logger.info("[+]Admin Services Ready\nenter 'help' for list of commands")
        command_list = self.SERVER_COMMANDS.command_instructions
        while True:
            command_input = str(input())
            command, argument = self.SERVER_COMMANDS.command_input(
                command_input)
            if command == "help":
                print(self.SERVER_COMMANDS.display_commands(command_list))
            elif command == "connections":
                with self.connections_lock:
                    print(self.SERVER_COMMANDS.display_connections(
                        connections=self.connections))
            elif command == "kick":
                with self.connections_lock:
                    reason = str(input("Please enter reason to kick:\n"))
                    self.system_logger.info(self.SERVER_COMMANDS.kick_user(ip_requested=argument,
                                                         connections=self.connections, reason=reason))
            elif command == "ban":
                with self.connections_lock:
                    reason = str(input("Please enter reason to kick:\n"))
                    self.system_logger.info(self.SERVER_COMMANDS.ban_user(ip_requested=argument,
                                                        connections=self.connections, reason=reason))
            elif command == "unban":
                self.system_logger.info(self.SERVER_COMMANDS.unban_user(ip_requested=argument))
            elif command == "servermessage":
                message_input = str(
                    input('[+]Please enter your server-wide message here: \n'))
                with self.message_lock:
                    self.message_queue.append(
                        self.SERVER_COMMANDS.server_message(message_input=message_input))
            elif command == "shutdown":
                decision = str(
                    input("Are you sure you want to shut down the server?\n[y/n]\n"))
                if decision.lower() == "y":
                    with self.connections_lock:
                        self.SERVER_COMMANDS.shutdown(
                            connections=self.connections)
                else:
                    self.system_logger.info("[+] Shutdown Cancelled")
            else:
                self.system_logger.info("[-]command not recognized")

    def main(self):
        self.system_logger.info(
            f"[+]Server Online at IP: {self.IP} PORT: {self.PORT}\n[+]Starting Processes")

        requests = Thread(target=self.take_requests)
        ping = Thread(target=self.ping)
        transmit = Thread(target=self.transmit)
        command = Thread(target=self.command_interface)

        threads = [requests, transmit, ping, command]

        for thread in threads:
            time.sleep(0.01)
            thread.start()


if __name__ == "__main__":
    self.system_logger.info(socket.gethostname())
    server = Server("0.0.0.0", 2222)
    server.main()
