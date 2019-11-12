#!/usr/bin/env python3
import socket, subprocess, os, threading, re, sys, time, smtplib, argparse, sqlite3
import decodeIDS
											#	|	socket.htons(3) or socket.getprotobyname('ggp') = gateway-to-gateway protocol	|
											#	|	cat /etc/protocols to see all the list of protocol numbers and the protocols	|
'''def MatchWithRule():
	write_log = open('logIDS.txt', 'a+')																
	write_log.write(f'{time.ctime()} ' + idsLOG + '\n')
	write_log.close()

	for rule in idsRULES:																
		if idsLOG == rule:
			print(f'[WARNING] RULE VIOLATION!: {idsLOG} :')
			SendAlert()'''

'''def InspectPayload():
	match = None
	for maliciousPATTERN in idsPATTERNS:
		hexPATTERN = ''.join('{:02x}'.format(ord(i)) for i in maliciousPATTERN)
		pattern = re.compile(hexPATTERN)
		
		if ipv4F8 == 6 or ipv6F4 == 6:													
			hexPAYLOAD = ''.join('{:02x}'.format(ord(i)) for i in tcpPAYLOAD.decode())
			match = pattern.finditer(hexPAYLOAD)
			if match:
				for x in match:
					print(f'[WARNING] MALICIOUS CODE FOUND IN TCP PAYLOAD {x}')
				match = None

		elif ipv4F8 == 17 or ipv6F4 == 17:												
			hexPAYLOAD = ''.join('{:02x}'.format(ord(i)) for i in udpPAYLOAD.decode())
			match = pattern.finditer(hexPAYLOAD)
			if match:
				for x in match:
					print(f'[WARNING] MALICIOUS CODE FOUND IN UDP PAYLOAD {x}')
				match = None

		else:
			pass'''

def StateTable():
	'''print(tcpF6)'''
	queryRESULT = None
	if tcpF6 == 2:
		tableES1 = (str(ipv4F10),str(tcpF0),str(ipv4F11),str(tcpF1),'SYN')
		dbCURSOR.execute('INSERT INTO StateTable VALUES (?,?,?,?,?)', tableES1)
		dbCONNECT.commit()
		print('entry created ES1')

	elif tcpF6 == 18:
		dbCURSOR.execute('SELECT * FROM StateTable WHERE srcIP=? AND srcPORT=? AND dstIP=? AND \
			dstPORT=? AND stateTCP=?',(str(ipv4F11),str(tcpF1),str(ipv4F10),str(tcpF0),'SYN'))
		queryRESULT = dbCURSOR.fetchone()
		if queryRESULT is None:
			print('[WARNING] MALICIOUS TCP PACKET FOUND')

		else:
			tableES2 = (str(ipv4F10),str(tcpF0),str(ipv4F11),str(tcpF1),'SYN/ACK')
			dbCURSOR.execute('INSERT INTO StateTable VALUES (?,?,?,?,?)', tableES2)
			dbCONNECT.commit()
			print('entry created ES2')
	
	elif tcpF6 == 16:
		tableES3 = (str(ipv4F10),str(tcpF0),str(ipv4F11),str(tcpF1),'ESTABLISHED')
		dbCURSOR.execute('INSERT INTO StateTable VALUES (?,?,?,?,?)',tableES3)
		dbCONNECT.commit()
		print('entry created ES3')

	else:
		pass

	dbCURSOR.execute('SELECT * FROM StateTable')
	print(dbCURSOR.fetchall())

'''def SendAlert():
	e_content = f'System Has Been Compromised. \n\n \
				Abnormal Condition Detected At {time.ctime()}'
	e_logmail = 'lmorningstarthedevil@gmail.com'
	e_recipient = 'MadawalaDW@gmail.com'

	try:
		print('connecting to smtp.google.com:587... ')
		mail_server = smtplib.SMTP('smtp.gmail.com', 587)
		print('[SUCCESSFUL] CONNECTED TO GMAIL SERVER')
	except:
		print('[ERROR] CANNOT CONNECT TO -smtp.google.com:587-')

	print('sending ehlo...')
	mail_server.ehlo()
	print('starting tls...')
	mail_server.starttls()

	print('logging to lmorningstarthedevil@gmail.com...')
	mail_server.login(e_logmail,'Pass@123')
	print('[SUCCESSFUL] LOGGED IN TO MAIL SERVER')

	print('sending the warning message...')
	mail_server.sendmail(e_logmail, e_recipient, e_content)
	print('[SUCCESSFUL] EMAIL SENT')
	mail_server.close()
	print('connection terminated...')'''


try:
	print('socket is creating...')
	connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	connection.bind(('lo', 0))													
	print('[SUCCESSFUL] SOCKET CREATED')
except socket.error as s_error:
	print('[ERROR] SOCKET FAILED TO FORM')
	print(f'[SOCKET ERROR] {s_error}')

if os.name == 'nt':
	print('enabling promiscuous mode...')							
	connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	print('[SUCCESSFUL] PROMISCUOUS MODE ON')

try:
	print('rules loading...')
	idsRULES = open('ruleIDS.txt').read().splitlines()				
	print('[SUCCESSFUL] RULES LOADED')
except:
	print('[ERROR] FAILED TO LOAD RULES')

try:
	print('patterns loading...')										
	idsPATTERNS = open('patternIDS.txt').read().splitlines()
	print('[SUCCESSFUL] PATTERNS LOADED')
except:
	print('[ERROR] FAILED TO LOAD PATTERNS')

try:
	print('loading databases...')
	dbCONNECT = sqlite3.connect(':memory:')
	dbCURSOR = dbCONNECT.cursor()
	print('creating state table...')
	dbCURSOR.execute('''CREATE TABLE StateTable 
		(srcIP text, srcPORT text, dstIP text, dstPORT text, stateTCP text )''')
	dbCONNECT.commit()
	print('[SUCCESSFUL] STATE TABLES LOADED')
except:
	print('[ERROR] FAILED TO LOAD STATE TABLE')

print('LISTNING FOR INCOMING TRAFFIC')

while True:
	data = connection.recvfrom(65535)[0]							
	
	idsLOG = None												
	tcpPAYLOAD = None; udpPAYLOAD = None; 
	ipv4F8 = None; ipv6F4 = None; tcpF6 = None;

	getETHERNET = decodeIDS.DecodeETHERNET(data[:14])
	ethernetF1 = getETHERNET.ethernetF1; ethernetF0 = getETHERNET.ethernetF0;
	ethernetF2 = getETHERNET.ethernetF2
	idsLOG = f'{ethernetF2} {ethernetF1}->{ethernetF0}' 						

	if getETHERNET.ethernetF2 == 56710:
		getIPV6 = decodeIDS.DecodeIPv6(data[14:54])
		ipv6F4 = getIPV6.ipv6F4; ipv6F6 = getIPV6.ipv6F6; ipv6F7 = getIPV6.ipv6F7;
		idsLOG = f'{ipv6F4} {ipv6F6}->{ipv6F7}'										

		if getIPV6.ipv6F4 == 58:
			getICMP = decodeIDS.DecodeICMP(data[54:62])

		elif getIPV6.ipv6F4 == 6:
			getTCP = decodeIDS.DecodeTCP(data[54:74])
			tcpF0 = getTCP.tcpF0; tcpF1 = getTCP.tcpF1; tcpF6 = getTCP.tcpF6;
			idsLOG = f'{ipv6F4} {ipv6F6}:{tcpF0}->{ipv6F7}:{tcpF1}'

			tcpPAYLOAD = data[74:]

		elif getIPV6.ipv6F4 == 17:
			getUDP = decodeIDS.DecodeUDP(data[54:62])
			udpF0 = getUDP.udpF0; udpF1 = getUDP.udpF1;
			idsLOG = f'{ipv6F4} {ipv6F6}:{udpF0}->{ipv6F7}:{udpF1}'				

			udpPAYLOAD = data[62:]
		else:
			pass

	elif getETHERNET.ethernetF2 == 1544:
		getARP  =  decodeIDS.DecodeARP(data[14:42])

	elif getETHERNET.ethernetF2 == 8:
		getIPV4 = decodeIDS.DecodeIPv4(data[14:34])
		ipv4F8 = getIPV4.ipv4F8; ipv4F10 = getIPV4.ipv4F10; ipv4F11 = getIPV4.ipv4F11;
		idsLOG = f'{ipv4F8} {ipv4F10}->{ipv4F11}'								

		if getIPV4.ipv4F8 == 1:
			getICMP = decodeIDS.DecodeICMP(data[34:42])

		elif getIPV4.ipv4F8 == 6:
			getTCP = decodeIDS.DecodeTCP(data[34:54])
			tcpF0 = getTCP.tcpF0; tcpF1 = getTCP.tcpF1; tcpF6 = getTCP.tcpF6;
			idsLOG = f'{ipv4F8} {ipv4F10}:{tcpF0}->{ipv4F11}:{tcpF1}'			

			tcpPAYLOAD = data[54:]

		elif getIPV4.ipv4F8 == 17:
			getUDP = decodeIDS.DecodeUDP(data[34:42])
			udpF0 = getUDP.udpF0; udpF1 = getUDP.udpF1;
			idsLOG = f'{ipv4F8} {ipv4F10}:{udpF0}->{ipv4F11}:{udpF1}'			

			udpPAYLOAD = data[42:]

		else:
			pass
	else:
		pass

	StateTable()

	'''thread01 = threading.Thread(target=MatchWithRule)
	thread02 = threading.Thread(target=InspectPayload)'''
	'''thread01.start()
	thread02.start()'''

	idsLOG = None



