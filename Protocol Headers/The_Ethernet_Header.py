#!/usr/bin/env python3
# ETH_P_IP       = 0x0800    # ternet Protocol packet 

import socket 
import binascii
import struct

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

get_eth_header = the_ethernet_header('10:10:10:10:10:10','20:20:20:20:20:20',0x0800)
get_eth_header.create_eth_header()
eth_frame_01 = get_eth_header.new_eth_header




