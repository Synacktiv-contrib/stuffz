#!/usr/bin/env python
#
# Dissipe - a Sage ERP X3 scrambled passwords decoder
#
# It can be used to decrypt various secrets used by Sage X3:
# database credentials, system credentials, license keys, etc.
# 
# !!! This tool does not decrypt "AUTILIS.NEWPAS" passwords !!!
#
# ex:
#
# $ ./dissipe_conf_decrypt.py tqsgrQxutgrTrsvatgr
# manager
#
# $ ./dissipe_conf_decrypt.py udoro2RgrsxuTrsvauzkpfqxuTzktmrxuTeRdosgrrw3Tw3
# change_on_install
#
#           -- nicolas.collignon@synacktiv.com
import sys

# do they really think this secret is used in the encryption ?
KEY = "x3 vient du froid"

K_CHARSET = 'cromanwqxfzpgedkvstjhyilu'
K_DELTA   = 'zxWyZxzvwYzxZXxxZWWyWxYXz'
K_SUM     = 'cf2tln3yuVkDr7oPaQ8bsSd4x'

# adxsrv.exe 1.5.0.0 -> .text:004030A0-004031FE
def sage_decrypt(xstr, key):

	# the key is the size of the key (size matters ..)
	k_len = len(key)

	out, i, j = '', 1, 0

	while i < len(xstr):

		k_off = K_CHARSET.find(xstr[i])
		if k_off < 0:
			raise ValueError('cannot decrypt')

		out += chr( (ord(K_DELTA[j]) - ord(xstr[i-1])) * k_len + k_off)
		if (k_off & 1) == 0:
			if xstr[i+1] != K_SUM[k_off]:
				raise ValueError('cannot decrypt')
			i += 1

		j += 1
		i += 2

	return out

if __name__ == '__main__':

	if len(sys.argv) != 2:
		sys.stdout.write('usage: %s [CRYPT:]passwd\n' % sys.argv[0])
		sys.exit(1)

	encrypted_pwd = sys.argv[1]
	if encrypted_pwd.startswith('CRYPT:'):
		encrypted_pwd = encrypted_pwd[6:]

	if encrypted_pwd:
		try:
			sys.stdout.write('%s\n' % sage_decrypt(encrypted_pwd, KEY))
		except ValueError:
			sys.stderr.write('error: cannot decrypt\n')

