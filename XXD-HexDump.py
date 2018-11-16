#!/usr/bin/env python3
import argparse
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('target_file', help='ENTER FILE NAME', type=str)
args = parser.parse_args()

subprocess.call('clear', shell=True)

try:
	open_the_file = open(args.target_file, 'r')		#open file

	the_offest = 0	#set offest

	while True:	
		read16chrs = open_the_file.read(16)	#read 16 chars
		'''print(read16chrs)'''
		if len(read16chrs) == 0:
			break		#if not break, then script will print nothing but keep looping

		'''hexed_output = ' '.join('{:02X}'.format(ord(chars)) for chars in read16chrs)
		print(hexed_output)'''

		xxd_output = '{:08x}'.format(the_offest) + ': '	#offest with 8 hexes
		xxd_output += ' '.join('{:02x}'.format(ord(chars)) for chars in read16chrs)	#modify variable
		'''print (xxd_output)'''

		dot_unreadable = ''.join([chars if ord(chars) < 128 and ord(chars) > 32 \
											else '.' for chars in read16chrs]) #.replace unreadables
		'''print(dot_unreadable)'''

		xxd_output += '  ' + dot_unreadable		#finally modify the variable to add the last line 

		the_offest += 16	#increment offset by 16 
		print(xxd_output)
except:
	print('[FALIURE] CANNOT FIND THE FILE')