#!/usr/bin/env python3
from ctypes import *
import fcntl
import struct
import os
import socket
import subprocess
import threading
import sys

class decode_ah_header(Structure):

    _fields_ = [
        ('nxthdr', c_ubyte),        #1 bytes    [8 bits]
        ('plen', c_ubyte),          #1 bytes    [8 bits]
        ('rserv', c_ushort),        #2 bytes    [16 bits]
        ('spi', c_uint32),          #4 bytes    [32 bits]
        ('seqno', c_uint32),        #4 bytes    [32 bits]
        ('audata', c_uint32*3),     #16 bytes   [96 bits]   total = 24 bytes 
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.next_header = self.nxthdr

class the_ah_header:

    def __init__(self):
        self.new_ah_header = None
        self.create_ah_header()

    def create_ah_header(self):
        self.ah_nxthdr = 4                       #in tunnel mode | 4 = 1pv4, 41 = ipv6
        self.ah_plen = 4
        self.ah_rserv = 0000
        self.ah_spi = 0x00000000
        self.ah_seqno = 1
        self.au_icv = b'0'

        self.new_ah_header = struct.pack('!bbhII12s', self.ah_nxthdr, self.ah_plen, \
                                self.ah_rserv, self.ah_spi, self.ah_seqno, self.au_icv)
        return self.new_ah_header

class decode_ipv4_header(Structure):

    _fields_ = [
        ('ver', c_ubyte, 4),    #0.5 bytes  [4 bits]
        ('ihl', c_ubyte, 4),    #0.5 bytes  [4 bits]
        ('tos', c_ubyte),       #1 bytes    [8 bits]
        ('tolen', c_ushort),    #2 bytes    [16 bits]
        ('id', c_ushort),       #2 bytes    [16 bits]
        ('offset', c_ushort),   #2 bytes    [16 bits]
        ('ttl', c_ubyte),       #1 bytes    [8 bits]
        ('proto', c_ubyte),     #1 bytes    [8 bits]
        ('ipcksm', c_ushort),   #2 bytes    [16 bits]
        ('ipsrc', c_uint32),    #4 bytes    [32 bits]
        ('ipdst', c_uint32),    #4 bytes    [32 bits]   total = 20 bytes
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.src_ip = None
        self.dst_ip = None  
        self.decode_ipv4s()
        self.protocol = self.proto

    def decode_ipv4s(self):
        raw_src_ip = struct.pack('@I',self.ipsrc)
        raw_dst_ip = struct.pack('@I',self.ipdst)
        self.src_ip = socket.inet_ntop(socket.AF_INET,raw_src_ip)
        self.dst_ip = socket.inet_ntop(socket.AF_INET,raw_dst_ip)

class the_ipv4_header:
    def __init__(self, src_address, dst_address):
        self.src_address = src_address
        self.dst_address = dst_address
        self.new_ipv4_header = None

    def create_ipv4_header(self):
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

        self.ip_proto = 51

        self.ip_chksm = 0 

        self.ip_src = socket.inet_aton(self.src_address) 
        self.ip_dst = socket.inet_aton(self.dst_address) 

        self.new_ipv4_header = struct.pack('!BBHHHBBH4s4s',  
        self.ip_ver, self.ip_tos, self.ip_tolen, self.ip_id, self.ip_flg, self.ip_ttl,\
        self.ip_proto, self.ip_chksm, self.ip_src, self.ip_dst) 

        return self.new_ipv4_header

def open_fd():
    TUNSETIFF = 0x400454ca          
    IFF_TUN = 0x0001                #flag - tun device
    IFF_TAP = 0x0002                #flag - tap device
    IFF_NO_PI = 0x1000              #don't provide packet information
    TUNSETOWNER = TUNSETIFF + 2     #to access by a normal user

    fd = os.open('/dev/net/tun', os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack('16sH', 'tun10'.encode(), IFF_TUN | IFF_NO_PI))
    fcntl.ioctl(fd, TUNSETOWNER, 1000)
    return fd

def received_by(the_fd):
    while True:
        r_data = receive_data.recvfrom(65535)[0] #r_data = [0], addr = [1] 
        v4_header = decode_ipv4_header(r_data[14:34])

        try:
            if v4_header.src_ip == '100.100.100.101':     #source address of the received packet
                os.write(the_fd, r_data[14:])       #do not include ethernet frame
                print('[SUCCSESS] WRITTEN TO TUN')
        except:
            print('[FALIURE] NOT WRITTEN TO TUN')


def send_to(the_fd):
    while True:
        s_data = os.read(the_fd, 4096)
        '''print(len(s_data))'''                       #must be equal to 28 = ipv4(20) + icmp(8)

        get_ipv4_address = the_ipv4_header('100.100.100.100','100.100.100.101') 
        get_ipv4_address.create_ipv4_header() 
        ipv4_packet_01 = get_ipv4_address.new_ipv4_header

        get_ah_header = the_ah_header()
        ah_header_01 = get_ah_header.new_ah_header
                                            #change parameters in a real implementation
        send_data.sendto(ipv4_packet_01 + ah_header_01 + s_data, (('127.0.0.1',0))) 


receive_data = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
receive_data.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
receive_data.bind(('lo',0))     #change to eth0 in when implement, change r_data size too

send_data = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
send_data.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
send_data.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

file_descriptor = open_fd()
t_01 = threading.Thread(target=received_by, args=(file_descriptor,))
t_02 = threading.Thread(target=send_to, args=(file_descriptor,))
t_01.start()
t_02.start()
