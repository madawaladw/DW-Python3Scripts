#!/usr/bin/env python3
import ctypes
import fcntl
import struct
import os
import socket
import subprocess
import threading
import sys

'''class the_ah_header(ctypes.Structure):

    _fields_ = [
        ('nxthdr', c_ubyte),        #1 bytes    [8 bits]
        ('plen', c_ubyte),          #1 bytes    [8 bits]
        ('rserv', c_ushort),        #2 bytes    [16 bits]
        ('spi', c_uint32),          #4 bytes    [32 bits]
        ('seqno', c_uint32),        #4 bytes    [32 bits]
        ('audata', c_uint32*3),     #16 bytes   [96 bits]
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.next_header = self.nxthdr

class create_ah_header:

    def __init__(self):
        self.new_ah_header = None
        self.create_ah_header()

    def create_ah_header(self):
        self.ah_nxthdr = 4                  #in tunnel mode | 4 = 1pv4, 41 = ipv6
        self.ah_plen = 4
        self.ah_rserv = 0
        self.ah_spi = 0
        self.ah_seqno = 1
        self.ah_audata = 0

        return self.new_ah_header = struct.pack('!BBH4s4s12s', self.ah_nxthdr, \
            self.ah_plen, self.ah_rserv, self.ah_spi, self.ah_seqno, self.ah_audata)

class the_ipv4_header:
    def __init__(self, src_address, dst_address):
        self.src_address = src_address
        self.dst_address = dst_address
        self.new_ipv4_header = None

    def create_ipv4_packet(self):
        ip_ver = 4  
        ip_ihl = 5  
        self.ip_ver = (ip_ver << 4) + ip_ihl 

        ip_dsc = 0
        ip_enc = 0
        self.ip_tos = (ip_dsc << 2) + ip_enc 

        self.ip_tolen = 0 

        self.ip_id = 54321 

        ip_default = 0 
        ip_dontfrag = 0 
        ip_morefrag = 0 
        ip_fragoff = 0 
        self.ip_flg = (ip_default << 7) + (ip_dontfrag << 6) + (ip_morefrag << 5) + \
        																	(ip_fragoff) 
        self.ip_ttl = 255 

        self.ip_proto = socket.IPPROTO_TCP #change this to ICMP and UDP when in need

        self.ip_chksm = 0 

        self.ip_src = socket.inet_aton(self.src_address) 
        self.ip_dst = socket.inet_aton(self.dst_address) 

        self.new_ipv4_header = struct.pack('!BBHHHBBH4s4s',  
        self.ip_ver, self.ip_tos, self.ip_tolen, self.ip_id, self.ip_flg, self.ip_ttl,\
        self.ip_proto, self.ip_chksm, self.ip_src, self.ip_dst) 

        return self.new_ipv4_header'''

def open_fd():
	TUNSETIFF = 0x400454ca			
	IFF_TUN = 0x0001				#flag - tun device
	IFF_TAP = 0x0002				#flag - tap device
	IFF_NO_PI = 0x1000				#don't provide packet information
	TUNSETOWNER = TUNSETIFF + 2		#to access by a normal user

	fd = os.open('/dev/net/tun', os.O_RDWR)
	fcntl.ioctl(fd, TUNSETIFF, struct.pack('16sH', 'tun10'.encode(), IFF_TUN | IFF_NO_PI))
	'''fcntl.ioctl(tun, TUNSETOWNER, 1000)'''
	return fd

def received_by(the_fd):
	while True:
	    r_data = receive_data.recvfrom(65535)[0] #r_data = [0], addr = [1] 
	    inner_ipv4 = r_data[34:54]

	    unpacked_iipv4 = struct.unpack('!BBHHHBBH4s4s', inner_ipv4)
	    inner_src = socket.inet_ntop(socket.AF_INET, unpacked_iipv4[8])

	    if inner_src == '100.100.100.101':		#source address of the received packet
	        os.write(the_fd.fileno(), r_data[34:])

'''def send_to(the_fd):
	while True:
		s_data = os.read(the_fd.fileno(), 4096)

		get_ipv4_address = the_ipv4_header('100.100.100.100','100.100.100.101') 
		get_ipv4_address.create_ipv4_packet() 
		ipv4_packet_01 = get_ipv4_address.new_ipv4_header 

		send_data.sendto(ipv4_packet_01 + s_data, (('100.100.100.101',0)))'''


receive_data = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

send_data = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
send_data.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
send_data.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

file_descriptor = open_fd()
t_01 = threading.Thread(target=received_by, args=(file_descriptor,))
'''t_02 = threading.Thread(target=send_to, args=(file_descriptor,))'''
t_01.start()
'''t_02.start()'''
