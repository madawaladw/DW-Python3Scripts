import socket
import sys
import threading

server_host = str(sys.argv[1])
server_port = int(sys.argv[2])
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.bind((server_host,server_port))
print ('IP {} AND PORT {} ARE BINDED' .format(server_host,server_port))

conn.listen(5)
clientsocket, address = conn.accept()
print ('CLIENT {} CONNECTED' .format(address))

def print_messages():
	while True:
		data = clientsocket.recv(1024)
		print ('\nMESSAGE FROM CLIENT > ', data)
def send_messages():
	while True:
		text = input('\nMESSAGE TO THE CLIENT > ')
		clientsocket.sendall(text.encode('utf-8'))

thread_1 = threading.Thread(target=print_messages)
thread_2 = threading.Thread(target=send_messages)
thread_1.start()
thread_2.start()
