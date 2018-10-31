import sys
import argparse
import subprocess
import socket
import struct                       #sys.stdout.write('string to print')
                                    #sys.stdout.flush() : flush out 
class flusher:

    def __init__(self, sys_std):
        self.sys_std = sys_std

    def write_to_shell(self, print_this):
        self.sys_std.write(print_this) #display on shell
        self.sys_std.flush() #flush the written output to shell

subprocess.call('clear', shell=True)

pass_to_flusher = flusher(sys.stdout) #create instance for flusher

parser = argparse.ArgumentParser()
parser.add_argument('target_ip', help='ENTER THE DESTINATION IP', type=str)
args = parser.parse_args()

target_port = 33434 #default port for UDP based tracert (UPD 33434)
maxhops =30 #maximum hop count is 30
ttl = 1

while True:
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    timeout = struct.pack('ll', 3, 0) #GNu timeval struct (seconds, micro-seconds)
    receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout) #set time
    receive_socket.bind(('',0))

    pass_to_flusher.write_to_shell('TTL {} '.format(ttl))

    send_socket.sendto(''.encode(), ((args.target_ip,target_port))) #send packet to target

    got_reply = False #if this becomes true, the loop will terminate
    tries = 3 #loop 3 times
    current_addr = ' -' #if addr=nothing, print '-'
    while got_reply != True and tries > 0: #while to loop 3 times or until get data
        try:
            data, addr = receive_socket.recvfrom(1024)
            got_reply = True #if data received, set got_reply to True to terminate loop
            current_addr = addr[0] #addr[0], because addr=([0]<ip>, [1]<port>)
        except:
            tries = tries - 1
            pass_to_flusher.write_to_shell('* ')

    send_socket.close() #close send socket
    receive_socket.close() #close receive socket

    if addr:
        try:
            host_by_name = socket.gethostbyaddr(current_addr)
            pass_to_flusher.write_to_shell('{} {} \n'.format(host_by_name[0],current_addr))
        except:
            pass_to_flusher.write_to_shell('{} \n'.format(current_addr))
    else:
        pass_to_flusher.write_to_shell('\n')

    ttl = ttl + 1
    if current_addr == args.target_ip or ttl > maxhops:
        break
