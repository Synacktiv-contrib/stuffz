#!/usr/bin/python
#
# Script to decrypt Juniper encrypted passwords and keys
#
# Fabien Perigaud - Synacktiv

#*-*coding:utf-8*-*

import sys
import argparse
import hashlib
from Crypto.Cipher import AES

unpad = lambda s : s[0:-ord(s[-1])]

# Master key from ssg5ssg20.6.3.0r19.0.bin
MASTER_KEY = "8931208db7970ffe241df20c32c55ab9".decode("hex")

SCRIPT_DESCRIPTION = """Script to decrypt Juniper screenOS encrypted passwords and keys
by fabien.perigaud <at> synacktiv.com

Example:
$ python %s -c hendeck:nbKZXUXUNfn+0msW6xCh+0rm+Dnx9nQ0hQ==
hendeck:test123
"""

def parse_arguments():
	parser = argparse.ArgumentParser(description=SCRIPT_DESCRIPTION,
					 formatter_class=argparse.RawDescriptionHelpFormatter)

	group = parser.add_mutually_exclusive_group(required=True)

	group.add_argument('-c', '--cipher', required=False, help="input cipher. Format must be\
	<user>:<base64_encoded_string> or <base64_encoded_string>")

	group.add_argument('-f', '--file', required=False, help="input file. Format must be\
	<user>:<base64_encoded_string> or <base64_encoded_string>, one occurence per line")

	options = parser.parse_args()

	return options

# magic N,s,C,n junk bytes added in base64 cipher
# at 0x8, 0xE, 0x12, 0x1A offsets
def sanitize_cipher(input_cipher):
	my_cipher = input_cipher
	user = "<none>"
	
	if input_cipher.find(':') != -1:
		splitted = input_cipher.split(':')
		user = splitted[0]
		my_cipher = splitted[1]

	if (len(my_cipher) >= 0x8 and 
	    my_cipher[0x8]== 'N' and 
	    my_cipher[0xE] == 's' and 
	    my_cipher[0x12] == 'C' and 
	    my_cipher[0x1A] == 'n'):
		my_cipher = my_cipher[:0x8] + my_cipher[0x8 + 1:0xE] + my_cipher[0xE + 1:0x12] + my_cipher[0x12 + 1:0x1A] + my_cipher[0x1A + 1:]
	else:
		print "Magic junk bytes not found, skipping cipher: '%s'" % input_cipher
		my_cipher = ""

	return (user, my_cipher)	

def decrypt_cipher(my_cipher):
	encoded_IV = my_cipher[:8]
	encoded_ciphered = my_cipher[8:]

	try:
		decoded_IV = encoded_IV.decode("base64")
		IV = hashlib.sha1(decoded_IV).digest()[:16]
	except:
		print "Could not decode IV, skipping cipher: '%s'" % my_cipher
		return ""

	try:
		decoded_ciphered = encoded_ciphered.decode("base64")
	except:
		print "Could not decode ciphered, skipping cipher: '%s'" % my_cipher
		return ""

	try:
    		aes = AES.new(MASTER_KEY, AES.MODE_CBC, IV)
    		cleartext = unpad(aes.decrypt(decoded_ciphered))
	except:
    		print "Could not decipher, skipping cipher: '%s'" % my_cipher
    		return ""

	clear_len = ord(cleartext[0])
	cleartext = cleartext[1:]
	if clear_len != len(cleartext):
		return cleartext + " /!\\ Bad length?!"

	return cleartext

if __name__=="__main__":
	options = parse_arguments()

	if options.cipher != None:
		user, my_cipher = sanitize_cipher(options.cipher)
		cleartext = decrypt_cipher(my_cipher)
		if cleartext != "":
			print "%s:%s" % (user,cleartext)
	elif options.file != None:
		with open(options.file) as f:
			for line in f:
				user, my_cipher = sanitize_cipher(line.strip())
				# assume malformed input cipher
				if my_cipher == "":
					continue
				cleartext = decrypt_cipher(my_cipher)
				if cleartext != "":
					print "%s:%s" % (user,cleartext)	

