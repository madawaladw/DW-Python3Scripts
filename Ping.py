#!/usr/bin/env python3
import socket
import struct
from ctypes import *
import time
import threading
import argparse

class the_ipv4_header(Structure):

    _fields_ = [
        ('ver', c_ubyte, 4),
        ('ihl', c_ubyte, 4),
        ('tos', c_ubyte),
        ('tolen', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('proto', c_ubyte),
        ('chksm', c_ushort),
        ('src', c_uint32),
        ('dst', c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.send_packet = None
        self.recv_ip = None
        self.decode_ipv4()
        self.ip_ttl = self.ttl
    
    def decode_ipv4(self):
        raw_ipv4_src = struct.pack('@I',self.src)
        self.recv_ip = socket.inet_ntop(socket.AF_INET,raw_ipv4_src)
        return

class the_icmp_segment(Structure):

    _fields_ = [
        ('ictype', c_ubyte),
        ('iccode', c_ubyte),
        ('chksm', c_ushort),
        ('id', c_ushort),
        ('seq', c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.recv_type = None
        self.recv_code = None
        self.decode_icmp()
        self.ic_seq = self.seq
    
    def decode_icmp(self):
        self.recv_type = self.ictype
        self.recv_code = self.iccode
        return

class make_new_headers:

    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.send_frame = None
        self.send_packet = None

    def make_icmp_seg(self):
        self.new_ictype = 8
        self.new_iccode = 0 
        self.new_chksm = 0xf7fd
        self.new_id = 1
        self.new_seq = 1

        self.send_frame = struct.pack('!bbHHh', self.new_ictype, self.new_iccode, self.new_chksm,\
                                                        self.new_id, self.new_seq)
        return self.send_frame 

    def make_ipv4_pac(self):
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
        self.ip_flg = (ip_default << 7) + (ip_dontfrag << 6) + (ip_morefrag << 5) + (ip_fragoff) 

        self.ip_ttl = 255 

        self.ip_proto = socket.IPPROTO_ICMP 

        self.ip_chksm = 0 

        self.ip_src = socket.inet_aton('172.16.125.184') 
        self.ip_dst = socket.inet_aton(self.target_ip) 


        self.send_packet = struct.pack('!BBHHHBBH4s4s',  
        self.ip_ver, self.ip_tos, self.ip_tolen, self.ip_id, self.ip_flg, self.ip_ttl, self.ip_proto,\
                                                            self.ip_chksm, self.ip_src, self.ip_dst) 

        return self.send_packet

parser = argparse.ArgumentParser()
parser.add_argument('target_ip', help='ENTER THE TARGET IP ADDRESS', type=str)
args = parser.parse_args()


connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

receive_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))


def send_request():
    while True:
        new_headers = make_new_headers(args.target_ip)
        new_headers.make_ipv4_pac()
        ipv4_packet_01 = new_headers.send_packet
        new_headers.make_icmp_seg()
        icmp_segment_01 = new_headers.send_frame

        connection.sendto(ipv4_packet_01 + icmp_segment_01,((args.target_ip,0)))
        time.sleep(1)

def receive_reply():
    while True:
        data = receive_socket.recvfrom(65535)[0]

        read_src_ip = the_ipv4_header(data[14:34])
        read_icmp_reply = the_icmp_segment(data[34:42])
    
        if read_src_ip.proto == 1 and read_src_ip.recv_ip == args.target_ip:
            if read_icmp_reply.recv_type == 0:
                print ('64 BYTES FROM {}: ICMP_SEQ={} TTL={}'.format(read_src_ip.recv_ip, \
                                        read_icmp_reply.ic_seq, read_src_ip.ip_ttl))
            elif read_icmp_reply.recv_type == 3:
                print ('DESTINATION HOST UNREACHABLE')

t_01 = threading.Thread(target=send_request)
t_02 = threading.Thread(target=receive_reply)
t_01.start()
t_02.start()
