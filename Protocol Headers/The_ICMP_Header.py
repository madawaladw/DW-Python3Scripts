#!/usr/bin/env python3
import socket
import struct

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

get_icmp_header = the_icmp_header()
get_icmp_header.create_icmp_header()
icmp_segment_01 = get_icmp_header.new_icmp_header