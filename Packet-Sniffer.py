#!/usr/bin/env python3
import socket
import ipaddress
from ctypes import *
import struct
import binascii             #0.5 bytes  [4 bits]    = c_ubyte(,4)
                            #1 bytes    [8 bits]    = c_ubyte
                            #2 bytes    [16 bits]   = c_ushort
                            #4 bytes    [32 bits]   = c_uint32
                            #6 bytes    [48 bits]   = c_unit16*3

class the_ethernet_frame(Structure):

    _fields_ = [
        ('dstmac', c_uint16*3), #6 bytes    [48 bits]
        ('srcmac', c_uint16*3), #6 bytes    [48 bits]
        ('etype', c_ushort),    #2 bytes    [16 bits]
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.dst_mac = None
        self.src_mac = None
        self.decode_macs()
        socket.htons(self.etype)

    def decode_macs(self):
        raw_dst_mac = binascii.hexlify(self.dstmac).decode('ascii')
        raw_src_mac = binascii.hexlify(self.srcmac).decode('ascii')
        self.dst_mac = ':'.join(raw_dst_mac[i:i+2] for i in range(0,12,2)).upper()
        self.src_mac = ':'.join(raw_src_mac[i:i+2] for i in range(0,12,2)).upper()
        return

class the_ipv4_packet(Structure):

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
        ('ipdst', c_uint32),    #4 bytes    [32 bits]
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
        return

class the_ipv6_packet(Structure):

    _fields_ = [
        ('v6ver', c_ubyte, 4),  #0.5 bytes  [4 bits]
        ('tcls', c_ubyte),      #1 bytes    [8 bits]
        ('flow', c_ushort),     #2.5 bytes  [20 bits]
        ('plen', c_ushort),     #2 bytes    [16 bits]
        ('nxhdr', c_ubyte),     #1 bytes    [8 bits]
        ('hops', c_ubyte),      #1 bytes    [8 bits]
        ('v6src', c_ulonglong*2),   #16 bytes   [128 bits]
        ('v6dst', c_ulonglong*2),   #16 bytes   [128 bits]
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.ipv6_ver = self.v6ver
        self.ipv6_src = None
        self.ipv6_dst = None
        self.decode_ipv6s()
        self.ipv6_nxthdr = self.nxhdr

    def decode_ipv6s(self):
        raw_ipv6_src = binascii.unhexlify(binascii.hexlify(self.v6src))
        raw_ipv6_dst = binascii.unhexlify(binascii.hexlify(self.v6dst))
        self.ipv6_src = socket.inet_ntop(socket.AF_INET6, raw_ipv6_src)
        self.ipv6_dst = socket.inet_ntop(socket.AF_INET6, raw_ipv6_dst)
        return

class the_icmp_segment(Structure):

    _fields_ = [
        ('type', c_ubyte),      #1 bytes    [8 bits]
        ('code', c_ubyte),      #1 bytes    [8 bits]
        ('icmcksm', c_ushort),  #2 bytes    [16 bits]
        ('id', c_ushort),       #2 bytes    [16 bits]
        ('seq', c_ushort),      #2 bytes    [16 bits]
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.icm_type = self.type
        self.icm_code = self.code


class the_tcp_segment(Structure):

    _fields_ = [
        ('tcpsrc', c_ushort),   #2 bytes    [16 bits]
        ('tcpdst', c_ushort),   #2 bytes    [16 bits]
        ('tcpsq', c_uint32),    #4 bytes    [32 bits]
        ('tcpack', c_uint32),   #4 bytes    [32 bits]
        ('offst', c_ubyte, 4),  #0.5 bytes  [4 bits]
        ('resrv', c_ubyte, 4),  #0.5 bytes  [4 bits]
        ('tcpflg', c_ubyte),    #1 bytes    [8 bits]
        ('wndow', c_ushort),    #2 bytes    [16 bits]
        ('tcpcksm', c_ushort),  #2 bytes    [16 bits]
        ('urgp', c_ushort),     #2 bytes    [16 bits]
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.tcp_src = socket.ntohs(self.tcpsrc)
        self.tcp_dst = socket.ntohs(self.tcpdst)

class the_udp_segment(Structure):

    _fields_ = [
        ('udpsrc', c_ushort),   #2 bytes    [16 bits]
        ('udpdst', c_ushort),   #2 bytes    [16 bits]
        ('udplen', c_ushort),   #2 bytes    [16 bits]
        ('udpcksm', c_ushort),  #2 bytes    [16 bits]
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.udp_src = socket.ntohs(self.udpsrc)
        self.udp_dst = socket.ntohs(self.udpdst)

connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

while True:
    data = connection.recvfrom(65535)[0]
    ethernet_frame_01 = the_ethernet_frame(data[:14])
    print ('++ LAYER 2 ++ [DST-MAC] {}  [SRC-MAC] {}  [TYPE] {} '.format(ethernet_frame_01.dst_mac,\
                                                 ethernet_frame_01.src_mac, ethernet_frame_01.etype))
    ipv6_packet_01 = the_ipv6_packet(data[14:])
    ipv4_packet_01 = the_ipv4_packet(data[14:])

    if ethernet_frame_01.etype == 8:
        print ('+++ LAYER 3 +++ [DST-IP] {}  [SRC-IP] {}  [PROTOCOL] {}'.format(ipv4_packet_01.dst_ip, \
                                                    ipv4_packet_01.src_ip, ipv4_packet_01.protocol))

        icmp_segment_01 = the_icmp_segment(data[34:])
        tcp_segment_01 = the_tcp_segment(data[34:])
        udp_segment_01 = the_udp_segment(data[34:])

        if ipv4_packet_01.protocol == 1:

            if icmp_segment_01.icm_type == 8 and icmp_segment_01.icm_code == 0:
                print('++++ LAYER 4 ++++ ECHO REQUEST [TYPE] {} [CODE] {} \n'.format \
                                                    (icmp_segment_01.icm_type, icmp_segment_01.icm_code)) 
            elif icmp_segment_01.icm_type == 0 and icmp_segment_01.icm_code == 0:
                print('++++ LAYER 4 ++++ ECHO REPLY [TYPE] {} [CODE] {} \n'.format \
                                                    (icmp_segment_01.icm_type, icmp_segment_01.icm_code))
            elif icmp_segment_01.icm_type == 13 and icmp_segment_01.icm_code == 0:
                print ('++++ LAYER 4 ++++ TIMESTAMP REQUEST [TYPE] {} [CODE] {} \n'.format \
                                                    (icmp_segment_01.icm_type, icmp_segment_01.icm_code)) 
            elif icmp_segment_01.icm_type == 14 and icmp_segment_01.icm_code == 0:
                print ('++++ LAYER 4 ++++ TIMESTAMP REPLY [TYPE] {} [CODE] {} \n'.format \
                                                    (icmp_segment_01.icm_type, icmp_segment_01.icm_code)) 
            elif icmp_segment_01.icm_type == 10 and icmp_segment_01.icm_code == 0:
                print ('++++ LAYER 4 ++++ ROUTER SOLICITATION [TYPE] {} [CODE] {} \n'.format \
                                                    (icmp_segment_01.icm_type, icmp_segment_01.icm_code)) 
            elif icmp_segment_01.icm_type == 9 and icmp_segment_01.icm_code == 0:
                print ('++++ LAYER 4 ++++ ROUTER ADVERTISEMENT [TYPE] {} [CODE] {} \n'.format \
                                                    (icmp_segment_01.icm_type, icmp_segment_01.icm_code))         
            else:
                print ('++++ LAYER 4 ++++ OTHER ICMP TYPE/CODE {} {} \n'.format(icmp_segment_01.icm_type, icmp_segment_01.icm_code))

        elif ipv4_packet_01.protocol == 6:
            print ('++++ LAYER 4 ++++ [DST-PORT] {}  [SRC-PORT] {} \n'.format(tcp_segment_01.tcp_dst, tcp_segment_01.tcp_src))

        elif ipv4_packet_01.protocol == 17:
            print ('++++ LAYER 4 ++++ [DST-PORT] {}  [SRC-PORT] {} \n'.format(udp_segment_01.udp_dst, udp_segment_01.udp_src))

        else:
            print ('\n')

    elif ethernet_frame_01.etype == 56710: 
        print ('+++ LAYER 3 +++ [VERSION] {} [DST-IP] {}  [SRC-IP] {}  [PROTOCOL] {}'.format(ipv6_packet_01.ipv6_ver, \
                                                ipv6_packet_01.ipv6_dst, ipv6_packet_01.ipv6_src, ipv6_packet_01.ipv6_nxthdr))
        if ipv6_packet_01.ipv6_nxthdr == 58:
            print('++++ LAYER 4 ++++ ICMP SEGMENT \n')

        elif ipv6_packet_01.ipv6_nxthdr == 6:
            print ('++++ LAYER 4 ++++ [DST-PORT] {}  [SRC-PORT] {} \n'.format(tcp_segment_01.tcp_dst, tcp_segment_01.tcp_src))

        elif ipv6_packet_01.ipv6_nxthdr == 17:
            print ('++++ LAYER 4 ++++ [DST-PORT] {}  [SRC-PORT] {} \n'.format(udp_segment_01.udp_dst, udp_segment_01.udp_src))
        else:
            print ('++++ LAYER 4 ++++ OTHER ICMP TYPE/CODE {} {} \n'.format(icmp_segment_01.icm_type, icmp_segment_01.icm_code))
    else:
        print ('\n')

