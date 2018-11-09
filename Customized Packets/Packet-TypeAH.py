#!/usr/bin/env python3
import socket
import struct
import time

class the_oipv4_header:
    def __init__(self, src_address, dst_address):
        self.src_address = src_address
        self.dst_address = dst_address
        self.new_ipv4_header = None

    def create_oipv4_packet(self):
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

        self.ip_proto = 51 		#6 = tcp, 17 = udp, 41 = ipv6, 50 = ipsec esp, 51 = ipsec ah

        self.ip_chksm = 0 

        self.ip_src = socket.inet_aton(self.src_address) 
        self.ip_dst = socket.inet_aton(self.dst_address) 


        self.new_ipv4_header = struct.pack('!BBHHHBBH4s4s',  
        self.ip_ver, self.ip_tos, self.ip_tolen, self.ip_id, self.ip_flg, self.ip_ttl, \
        self.ip_proto, self.ip_chksm, self.ip_src, self.ip_dst) 

        return self.new_ipv4_header

class the_iipv4_header:
    def __init__(self, src_address, dst_address):
        self.src_address = src_address
        self.dst_address = dst_address
        self.new_ipv4_header = None

    def create_iipv4_packet(self):
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

        self.ip_proto = 1 	#1 = icmp, 6 = tcp, 17 = udp, 41 = ipv6, 50 = ipsec esp, 51 = ipsec ah

        self.ip_chksm = 0 

        self.ip_src = socket.inet_aton(self.src_address) 
        self.ip_dst = socket.inet_aton(self.dst_address) 


        self.new_ipv4_header = struct.pack('!BBHHHBBH4s4s',  
        self.ip_ver, self.ip_tos, self.ip_tolen, self.ip_id, self.ip_flg, self.ip_ttl, \
        self.ip_proto, self.ip_chksm, self.ip_src, self.ip_dst) 

        return self.new_ipv4_header

class the_ah_header:

    def __init__(self):
        self.new_ah_header = None
        self.create_ah_header()

    def create_ah_header(self):
        self.ah_nxthdr = 4                  #in tunnel mode | 4 = 1pv4, 41 = ipv6
        self.ah_plen = 4
        self.ah_rserv = 0000
        self.ah_spi = 0x00000000
        self.ah_seqno = 1
        self.au_icv = b'0'

        self.new_ah_header = struct.pack('!bbhII12s', self.ah_nxthdr, self.ah_plen, self.ah_rserv, \
        												self.ah_spi, self.ah_seqno, self.au_icv)
        return self.new_ah_header

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

connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

while True:
	get_oipv4_address = the_oipv4_header('100.100.100.101','100.100.100.100') 
	get_oipv4_address.create_oipv4_packet() 
	ipv4_packet_01 = get_oipv4_address.new_ipv4_header

	get_ah_header = the_ah_header()
	ah_header_01 = get_ah_header.new_ah_header
	'''print (len(ah_header_01))'''

	get_iipv4_address = the_iipv4_header('100.100.100.101','100.100.100.100') 
	get_iipv4_address.create_iipv4_packet() 
	ipv4_packet_02 = get_iipv4_address.new_ipv4_header

	get_icmp_header = the_icmp_header()
	get_icmp_header.create_icmp_header()
	icmp_segment_01 = get_icmp_header.new_icmp_header
                                                        #must change addresses to appropriate ip address
	connection.sendto(ipv4_packet_01 + ah_header_01 + ipv4_packet_02 + icmp_segment_01 ,(('127.0.0.1',0)))
	print('SENT')
	time.sleep(1)