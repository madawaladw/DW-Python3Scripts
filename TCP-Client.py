import socket
import sys
import threading 

target_host = str(sys.argv[1])
target_port = int(sys.argv[2])

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

conn.connect((target_host, target_port))
print ('CONNECTION ESTABLISHED WITH {} PORT {}'.format(target_host, target_port))

def send_message():
	while True:
		text = input('\nMESSAGE TO THE SERVER > ')
		conn.sendall(text.encode('utf-8'))
def print_message():
	while True:
		data = conn.recv(1024)
		print ('\nSERVER SENT > ', data)

thread_1 = threading.Thread(target=send_message)
thread_2 = threading.Thread(target=print_message)
thread_1.start()
thread_2.start()