#!/usr/bin/env python3
import socket
import struct

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

        self.ip_proto = socket.IPPROTO_TCP #change this to ICMP and UDP when in need

        self.ip_chksm = 0 

        self.ip_src = socket.inet_aton(self.src_address) 
        self.ip_dst = socket.inet_aton(self.dst_address) 


        self.new_ipv4_header = struct.pack('!BBHHHBBH4s4s',  
        self.ip_ver, self.ip_tos, self.ip_tolen, self.ip_id, self.ip_flg, self.ip_ttl, \
        self.ip_proto, self.ip_chksm, self.ip_src, self.ip_dst) 

        return self.new_ipv4_header

        
get_ipv4_address = the_ipv4_header('10.10.10.10','20.20.20.20') 
get_ipv4_address.create_ipv4_packet() 
ipv4_packet_01 = get_ipv4_address.new_ipv4_header 
