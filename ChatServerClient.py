import socket
from threading import Thread
from json import loads, dumps
import json
import re
import os
import time
from datetime import datetime


class Client:
	def __init__(self, ip, port, displayname="Guest"):
		self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connection.connect((ip, port))
		self.mqueue = []
		self.name = displayname
	
	def pack_and_send(self, message):
		json_message = dumps(message)
		self.connection.send(json_message.encode('utf-8'))
	
	def full_receive(self):
		message = ""
		while True:
			try:
				message = message + loads(self.connection.recv(1024).decode('utf-8'))
				return message
			except ValueError:
				continue
	
	def command_list_display(self, command_list):
		print("###COMMAND LIST###\n")
		for name, description in command_list.items():
			print(f"	{name}: {description}")
			
	def disconnect(self):
		print("[+]Disconnected from the server")
		self.connection.close()
		os._exit(1)
		
	def execute_command(self, command):
		command_list = {"help":"display all commands","disconnect":"disconnect from the server"}
		if command[0].lower() == "&&help":
			self.command_list_display(command_list)
		
		if command[0].lower() == "&&disconnect":
			self.disconnect()
				
	def send_messages(self):
		print("[+]Ready to send messages!")
		while True:
			try:
				message = str(input(""))
				if message[0:2] != "&&":
					formatted_message = f"{datetime.now().strftime('%H:%M:%S')}--{self.name}: {message}"
					self.pack_and_send(formatted_message)
				else:
					self.execute_command(message.split(" "))
			except OSError:
				continue
			except ConnectionResetError:
				print("[-] Connection was Lost")
				os._exit(1)
			
	def receive_message(self):
		print("[+]Ready to receive messages!")
		while True:
			try:
				message = self.full_receive()
				self.mqueue.append(message)
			except OSError:
				continue
			except ConnectionResetError:
				print("[-] Connection was Lost")
				os._exit(1)
				
	def print_messages(self):
		while True:
			try:
				if self.mqueue:
					for message in self.mqueue:
						if message[0:2] and message[-2:] != "&&" and f"{self.name}" not in message[:20]:
							print(message)
							self.mqueue.remove(message)
						elif message == "&&SERVER SHUTDOWN INITIATED&&":
							print("[!] Server shutdown was initiated!")
							os._exit(1)
						else:
							self.mqueue.remove(message)
			except RuntimeError:
				continue
				
	def main(self):
		sender = Thread(target=self.send_messages)
		receiver = Thread(target=self.receive_message)
		printer = Thread(target=self.print_messages)
		
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
			
	client = Client("", 2222, displayname=name)
	client.main()
    
