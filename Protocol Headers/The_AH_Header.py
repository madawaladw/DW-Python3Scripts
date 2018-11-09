#!/usr/bin/env python3
import socket
import struct
                            #f1 = 1 bytes    [8 bits]
                            #f2 = 1 bytes    [8 bits]
                            #f3 = 2 bytes    [16 bits]
                            #f4 = 4 bytes    [32 bits]
                            #f5 = 4 bytes    [32 bits]
                            #f6 = 16 bytes   [96 bits]
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

get_ah_header = the_ah_header()
ah_header_01 = get_ah_header.new_ah_header
'''print(len(ah_header_01))'''