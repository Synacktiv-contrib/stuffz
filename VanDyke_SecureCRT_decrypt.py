#!/usr/bin/env python
#
# Decrypt SSHv2 passwords stored in VanDyke SecureCRT session files
# Can be found on Windows in:
#   %APPDATA%\VanDyke\Config\Sessions\sessionname.ini
# Tested with version 7.2.6 (build 606) for Windows
# Eloi Vanderbeken - Synacktiv

from Crypto.Cipher import Blowfish
import argparse
import re

def decrypt(password) :
	c1 = Blowfish.new('5F B0 45 A2 94 17 D9 16 C6 C6 A2 FF 06 41 82 B7'.replace(' ','').decode('hex'), Blowfish.MODE_CBC, '\x00'*8)
	c2 = Blowfish.new('24 A6 3D DE 5B D3 B3 82 9C 7E 06 F4 08 16 AA 07'.replace(' ','').decode('hex'), Blowfish.MODE_CBC, '\x00'*8)
	padded = c1.decrypt(c2.decrypt(password.decode('hex'))[4:-4])
	p = ''
	while padded[:2] != '\x00\x00' :
		p += padded[:2]
		padded = padded[2:]
	return p.decode('UTF-16')

REGEX_HOSTNAME = re.compile(ur'S:"Hostname"=([^\r\n]*)')
REGEX_PASWORD = re.compile(ur'S:"Password"=u([0-9a-f]+)')
REGEX_PORT = re.compile(ur'D:"\[SSH2\] Port"=([0-9a-f]{8})')
REGEX_USERNAME = re.compile(ur'S:"Username"=([^\r\n]*)')

def hostname(x) :
	m = REGEX_HOSTNAME.search(x)
	if m :
		return m.group(1)
	return '???'

def password(x) :
	m = REGEX_PASWORD.search(x)
	if m :
		return decrypt(m.group(1))
	return '???'

def port(x) :
	m = REGEX_PORT.search(x)
	if m :
		return '-p %d '%(int(m.group(1), 16))
	return ''

def username(x) :
	m = REGEX_USERNAME.search(x)
	if m :
		return m.group(1) + '@'
	return ''

parser = argparse.ArgumentParser(description='Tool to decrypt SSHv2 passwords in VanDyke Secure CRT session files')
parser.add_argument('files', type=argparse.FileType('r'), nargs='+',
	help='session file(s)')
args = parser.parse_args()


for f in args.files :
	c = f.read().replace('\x00', '')
	print f.name
	print "ssh %s%s%s # %s"%(port(c), username(c), hostname(c), password(c))


