#!/usr/bin/env python
import socket, binascii, struct
#	|___________________________________________________________________________________________________________________________________|
#	|	0.5 bytes  [4 bits]    = c_ubyte(,4)    |	1 bytes = B 	[unassigned char]		|	socket.htons(0x0800) = 8	[IPv4]		|
#	|	1 bytes    [8 bits]    = c_ubyte	 	|	2 bytes = H 	[unassigned short]		|	socket.htons(0x0806) = 1544	[ARP]		|
#	|	2 bytes    [16 bits]   = c_ushort	 	|	4 bytes = L 	[unassigned long]		|	socket.htons(0x086DD)= 56710[IPv6]		|
#	|	4 bytes    [32 bits]   = c_uint32	 	|	4 bytes = I		[unassigned int]		|___________________________________________|
#	|	6 bytes    [48 bits]   = c_unit16*3 	|	8 bytes = Q		[unassigned long long]	|	'@6s6sH'	=	Native Byte Order		|
#	|											|	20 bytes = 20s 	[char[] size of 1byte]	|	'!6s6sH'	=	Network Byte Order		|
#	|___________________________________________|___________________________________________|___________________________________________|
#	|																																	|
class DecodeETHERNET:

	def __init__(self, dataNEW):
		dataUNPACK = struct.unpack('>6s6sH', dataNEW)

		self.ethernetF0 = binascii.hexlify(dataUNPACK[0]).decode()		#	|	Destination MAC 	|	6 bytes		[48 bits]			|
		self.ethernetF1 = binascii.hexlify(dataUNPACK[1]).decode()		#	|	Source MAC 			|	6 bytes		[48 bits]			|
		self.ethernetF2 = socket.ntohs(dataUNPACK[2])					#	|	Ether Type 			|	2 bytes		[16 bits]	= 14 	|

class DecodeARP:

	def __init__(self, dataNEW):
		dataUNPACK = struct.unpack('>HHBBH6s4s6s4s', dataNEW)

		self.arpF0 = dataUNPACK[0]										#	|	Hardware Type 		|	2 bytes		[16 bits]			|
		self.arpF1 = hex(dataUNPACK[1])									#	|	Protocol Type 		|	2 bytes		[16 bits]			|
		self.arpF2 = dataUNPACK[2]										#	|	HW Add Len 			|	1 bytes		[8 bits]			|
		self.arpF3 = dataUNPACK[3]										#	|	Proto Add Len		|	1 bytes		[8 bits]			|
		self.arpF4 = dataUNPACK[4]										#	|	OP Code 			|	2 bytes		[16 bits]			|
		self.arpF5 = binascii.hexlify(dataUNPACK[5]).decode()			#	|	Sender MAC 			|	6 bytes		[48 bits]			|
		self.arpF6 = socket.inet_ntop(socket.AF_INET, dataUNPACK[6])	#	|	Sender IP 			|	4 bytes		[32 bits]			|
		self.arpF7 = binascii.hexlify(dataUNPACK[7]).decode()			#	|	Targer MAC 			|	6 bytes		[48 bits]			|
		self.arpF8 = socket.inet_ntop(socket.AF_INET, dataUNPACK[8])	#	|	Target IP			|	4 bytes		[32 bits]	= 28	|

class DecodeIPv4:

	def __init__(self, dataNEW):
		dataUNPACK = struct.unpack('>BBHHHBBH4s4s', dataNEW)

		self.ipv4F0 = (dataUNPACK[0] >> 4)								#	|	Version				|	0.5 bytes	[4 bits]			|
		self.ipv4F1 = (dataUNPACK[0] & 0xF)								#	|	Header Legnth		|	0.5 bytes	[4 bits]			|
		self.ipv4F2 = dataUNPACK[1]										#	|	Type Of Service		|	1 bytes		[8 bits]			|
		self.ipv4F3 = dataUNPACK[2]										#	|	Total Legnth		|	2 bytes		[16 bits]			|
		self.ipv4F4 = hex(dataUNPACK[3]) 								#	|	Identification		|	2 bytes		[16 bits]			|
		self.ipv4F5 = (dataUNPACK[4]) >> 13								#	|	Flags				|	0.3 bytes	[3 bits]			|
		self.ipv4F6 = (dataUNPACK[4] & 0x1FFF)							#	|	Fragment Offset		|	1.3 bytes	[13 bits]			|	
		self.ipv4F7 = dataUNPACK[5]										#	|	Time To Live		|	1 bytes		[8 bits]			|
		self.ipv4F8 = dataUNPACK[6]										#	|	Protocol			|	1 bytes		[8 bits]			|
		self.ipv4F9 = hex(dataUNPACK[7])								#	|	Header Checksum		|	2 bytes		[16 bits]			|
		self.ipv4F10 = socket.inet_ntop(socket.AF_INET, dataUNPACK[8])	#	|	Source IP 			|	4 bytes		[32 bits]			|
		self.ipv4F11 = socket.inet_ntop(socket.AF_INET, dataUNPACK[9])	#	|	Destination IP 		|	4 bytes		[32 bits]	= 20	|

class DecodeIPv6:

	def __init__(self, dataNEW):
		dataUNPACK = struct.unpack('>IHBB16s16s', dataNEW)

		self.ipv6F0 = (dataUNPACK[0] >> 28)								#	|	Version 			|	0.5 bytes	[4 bits]			|
		self.ipv6F1 = (dataUNPACK[0] >> 20) & 0xFF 						#	|	Priority/Traffic Cls|	1 bytes 	[8 bits]			|
		self.ipv6F2 = hex(dataUNPACK[0] & 0xFFFFF) 						#	|	Flow Label 			|	2.5 bytes	[20 bits]			|
		self.ipv6F3 = dataUNPACK[1]										#	|	Payload Legnth 		|	2 bytes		[16 bits]			|
		self.ipv6F4 = dataUNPACK[2]										#	|	Next Header 		|	1 byte 		[8 bits]			|
		self.ipv6F5 = dataUNPACK[3]										#	|	Hop Limit 			|	1 byte 		[8 bits]			|
		self.ipv6F6 = socket.inet_ntop(socket.AF_INET6, dataUNPACK[4])	#	|	Source IPv6 		|	16 bytes	[128 bits]			|
		self.ipv6F7 = socket.inet_ntop(socket.AF_INET6, dataUNPACK[5])	#	|	Destination IPv6 	|	16 bytes 	[128 bits]	= 40	|

class DecodeICMP:

	def __init__(self, dataNEW):
		dataUNPACK = struct.unpack('>BBHHH', dataNEW)

		self.icmpF0 = dataUNPACK[0]										#	|	Type 				|	1 bytes    	[8 bits]			|
		self.icmpF1 = dataUNPACK[1]										#	|	Code 				|	1 bytes    	[8 bits]			|
		self.icmpF2 = hex(dataUNPACK[2])								#	|	Checksum 			|	2 bytes    	[16 bits]			|
		self.icmpF3 = dataUNPACK[3]										#	|	Identifier			|	2 bytes    	[16 bits]			|
		self.icmpF4 = dataUNPACK[4]										#	|	Seqence Number		|	2 bytes    	[16 bits]	= 8		|

class DecodeTCP:

	def __init__(self, dataNEW):
		dataUNPACK = struct.unpack('>HHIIBBHHH', dataNEW)

		self.tcpF0 = dataUNPACK[0]										#	|	Source Port 		|	2 bytes    	[16 bits]			|
		self.tcpF1 = dataUNPACK[1]										#	|	Destination Port 	|	2 bytes    	[16 bits]			|
		self.tcpF2 = dataUNPACK[2]										#	|	Sequence Number 	|	4 bytes    	[32 bits]			|
		self.tcpF3 = dataUNPACK[3]										#	|	Ack Number 			|	4 bytes    	[32 bits]			|
		self.tcpF4 = (dataUNPACK[4]) >> 4								#	|	Offset (H. Legnth) 	|	0.5 bytes  	[4 bits]			|
		self.tcpF5 = (dataUNPACK[4] & 0xF)								#	|	Reserved 			|	0.5 bytes  	[4 bits]			|
		self.tcpF6 = dataUNPACK[5]										#	|	Flags 				|	1 bytes    	[8 bits]			|
		self.tcpF7 = socket.ntohs(dataUNPACK[6])						#	|	Window Size 		|	2 bytes    	[16 bits]			|
		self.tcpF8 = hex(dataUNPACK[7])									#	|	Checksum 			|	2 bytes    	[16 bits]			|
		self.tcpF9 = dataUNPACK[8]										#	|	Urgent Pointer 		|	2 bytes    	[16 bits]	= 20	|

class DecodeUDP:

	def __init__(self, dataNEW):
		dataUNPACK = struct.unpack('>HHHH', dataNEW)

		self.udpF0 = dataUNPACK[0]										#	|	Source Port 		|	2 bytes    	[16 bits]			|
		self.udpF1 = dataUNPACK[1]										#	|	Destination Port 	|	2 bytes    	[16 bits]			|
		self.udpF2 = dataUNPACK[2]										#	|	Legnth 				|	2 bytes    	[16 bits]			|
		self.udpF3 = hex(dataUNPACK[3])									#	|	Checksum 			|	2 bytes    	[16 bits]	= 8		|


