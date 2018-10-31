import socket
import subprocess
import argparse
import threading
import queue


def port_scan(target_port):
	connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		connection.connect((args.target_address,target_port))
		with lock:
			print ('PORT {} IS OPEN'.format(target_port))
			connection.close()
	except:
		pass

def threader(): #this function will thread 100 (target=threader)
	while True:
		port_nums = q.get()
		port_scan(port_nums)
		q.task_done()


subprocess.call('clear', shell=True)

parser = argparse.ArgumentParser()
parser.add_argument('target_address', help='ENTER THE TARGET IP', type=str)
args = parser.parse_args()

lock = threading.Lock() #lock to prevent printing out of sequence

q = queue.Queue()

for threads in range(100): #100 threads
	t = threading.Thread(target=threader)
	t.daemon = True
	t.start()

for port_nums in range(1,101): #put ports numbers to the queue
	q.put(port_nums)

q.join()

