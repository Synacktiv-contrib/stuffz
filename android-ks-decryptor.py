#!/usr/bin/env python3
# 
# Script to decode and decrypt Android Keystores (only software).
# 
# Julien Legras - Synacktiv
# Thomas Etrillard - Synacktiv
# 
#coding: utf-8

# Docs and usesful links
# https://nelenkov.blogspot.com/2015/06/keystore-redesign-in-android-m.html
# http://www.cs.ru.nl/~joeri/papers/spsm14.pdf
# http://androidxref.com/6.0.1_r10/xref/system/security/keystore/keystore.cpp#587
# https://github.com/googlesamples/android-BasicAndroidKeyStore/
# https://developer.android.com/training/articles/keystore

from passlib.crypto.digest import pbkdf2_hmac
from hashlib import md5
from Crypto.Cipher import AES
import sys
import struct
import base64
import os
from io import BytesIO
import argparse
import textwrap

KEY_BLOB_TYPE = { 1 : "generic", 2: "master_key", 3: "key_pair", 4: "keymaster_10"}

AES_BLOCK_SIZE = int(128 / 8)
SALT_SIZE = 16
MD5_DIGEST_LENGTH = 16
PBKDF2_ALGO = "sha1"
KEK_LENGTH = int(128 / 8)
KEK_ROUNDS = 8192
INT_SIZE = 4
KEYSTORE_FLAG_ENCRYPTED = 1 << 0
KEYSTORE_FLAG_SUPER_ENCRYPTED = 4 << 0
KEYSTORE_FLAG_FALLBACK = 1 << 1
HEADER_SIZE = 4

# PKEY TYPES
EVP_PKEY_RSA = 6
EVP_PKEY_DSA = 116
EVP_PKEY_EC = 408

# MAGICS
SOFT_KM_MAGIC    = 0x504b2338
SOFT_KM_MAGIC_LE = 0x38234b50

# TAG TYPES
KM_INVALID = 0 << 28
KM_ENUM = 1 << 28
KM_ENUM_REP = 2 << 28
KM_INT = 3 << 28
KM_INT_REP = 4 << 28
KM_LONG = 5 << 28
KM_DATE = 6 << 28
KM_BOOL = 7 << 28
KM_BIGNUM = 8 << 28
KM_BYTES = 9 << 28
KM_LONG_REP = 10 << 28

TAG_PURPOSE = KM_ENUM_REP | 1
TAG_ALGORITHM = KM_ENUM | 2
TAG_KEY_SIZE = KM_INT | 3
TAG_BLOCK_MODE = KM_ENUM_REP | 4
TAG_DIGEST = KM_ENUM_REP | 5
TAG_PADDING = KM_ENUM_REP | 6
TAG_ROOT_OF_TRUST = KM_BYTES | 704

ALGORITHM_RSA = 1
ALGORITHM_EC = 3
ALGORITHM_AES = 32
ALGORITHM_HMAC = 128

ALGORITHM_NAME = {
	1: 'RSA',
	3: 'EC',
	32: 'AES',
	33: '3DES',
	128: 'HMAC'
}

class AuthorizationSet:
	def __init__(self):
		self.tags = []
	
	def get_algorithm_name(self):
		for tag, ti in self.tags:
			if tag == TAG_ALGORITHM:
				return ALGORITHM_NAME[ti]


	def parse(blob, offset):
		auth_set = AuthorizationSet()
		b = BytesIO(blob[offset:])
		indirect_data_size, = struct.unpack("<i", b.read(INT_SIZE))
		if indirect_data_size > 0:
			indirect_data = b.read(indirect_data_size)

		elts_cnt, elts_size = struct.unpack("<ii", b.read(2*INT_SIZE))
		for i in range(elts_cnt):
			tag, = struct.unpack("<i", b.read(INT_SIZE))
			if tag == -1:
				continue

			tag_type = tag & (0XF << 28)
			if tag_type == KM_INVALID:
				break
			elif tag_type in [KM_ENUM, KM_ENUM_REP, KM_INT, KM_INT_REP]:
				ti, = struct.unpack("<i", b.read(INT_SIZE))
				auth_set.tags.append((tag, ti))
			elif tag_type in [KM_LONG, KM_LONG_REP, KM_DATE]:
				ti, = struct.unpack("<l", b.read(INT_SIZE))
				auth_set.tags.append((tag, ti))
			elif tag_type == KM_BOOL:
				ti = b.read(1)
				auth_set.tags.append((tag, ti))
			elif  tag_type in [KM_BIGNUM, KM_BYTES]:
				l, o = struct.unpack("<ii", b.read(2*INT_SIZE))
				l.read(o) # skip
				ti = b.read(l)
				auth_set.tags.append((tag, ti))
			else:
				raise ValueError

		return auth_set


class KeystorePrinters:
	def show_key_pair(ks, output_filename=None, dump=False):
		if dump and not output_filename:
			dump = False

		b = BytesIO(ks.value)
		magic = b.read(INT_SIZE)
		typ, = struct.unpack(">i", b.read(INT_SIZE))
		if typ not in [EVP_PKEY_EC, EVP_PKEY_RSA, EVP_PKEY_DSA]:
			# maybe an old format, RSA by default
			typ = EVP_PKEY_RSA
			pubkey_len = typ
		else:
			pubkey_len, = struct.unpack(">i", b.read(INT_SIZE))

		if pubkey_len > 0:
			pubkey_bytes = b.read(pubkey_len)

		privkey_len, = struct.unpack(">i", b.read(INT_SIZE))
		privkey_bytes = b.read(privkey_len)

		alg_name = None
		if typ == EVP_PKEY_RSA:
			alg_name = "RSA"
		elif typ == EVP_PKEY_DSA:
			alg_name = "DSA"
		elif typ == EVP_PKEY_EC:
			alg_name = "EC"
		else:
			raise ValueError

		output = sys.stdout
		if dump: output = open(output_filename, 'w')
		output.write("-----BEGIN %s PRIVATE KEY-----\n" % alg_name)
		output.write(textwrap.fill(base64.b64encode(privkey_bytes).decode('utf-8'), 64))
		output.write("\n-----END %s PRIVATE KEY-----\n" % alg_name)
		if dump: output.close()


	def show_keymaster_10(ks, output_filename=None, dump=False):
		b = BytesIO(ks.value)
		version = b.read(1)

		length, = struct.unpack("<i", b.read(INT_SIZE))
		privkey_bytes = b.read(length)

		keymat_length, = struct.unpack("<i", b.read(INT_SIZE))
		keymat = b.read(keymat_length)

		tag_length, = struct.unpack("<i", b.read(INT_SIZE))
		tag = b.read(tag_length)

		cipher = keymat + tag

		b.read(INT_SIZE)
		authorizations = b.read()
		auth_set = AuthorizationSet.parse(authorizations, 0)

		alg_name = auth_set.get_algorithm_name()

		output = sys.stdout
		if dump: output = open(output_filename, 'w')
		output.write("-----BEGIN %s PRIVATE KEY-----\n" % alg_name)
		output.write(textwrap.fill(base64.b64encode(privkey_bytes).decode('utf-8'), 64))
		output.write("\n-----END %s PRIVATE KEY-----\n" % alg_name)
		if dump: output.close()

	def show_master_key(ks):
		print("master key: %s" % (ks.value.hex()))

	def show_generic(ks, output_filename=None, dump=False):
		output = sys.stdout
		if dump: output = open(output_filename, 'w')
		if ks.value[:2] == b'\x30\x82':
			output.write("-----BEGIN CERTIFICATE-----\n")
			output.write(textwrap.fill(base64.b64encode(ks.value).decode('utf-8'), 64))
			output.write("\n-----END CERTIFICATE-----\n")
		else:
			output.write(ks.value.decode('utf-8'))
		if dump: output.close()


class KeystoreBlob:
	PRINTERS = [
		None,
		KeystorePrinters.show_generic,
		KeystorePrinters.show_master_key,
		KeystorePrinters.show_key_pair,
		KeystorePrinters.show_keymaster_10
	]

	def __init__(self):
		self.value = None
		self.description = None
		self.version = None
		self.type = None
		self.flags = None
		self.info = None
		self.blob = None
		self.blob_length = None


	def parse_master_key(filename, password):
		ksb = KeystoreBlob()
		with open(filename, "rb") as ksb.blob:
			ksb.parse_header()
			iv = ksb.blob.read(AES_BLOCK_SIZE)
			b = ksb.blob.read()
			encrypted, salt = b[:-ksb.info], b[-SALT_SIZE:]

			kek = ksb.generate_kek(password, salt)
			decrypted = BytesIO(ksb.decrypt(iv, encrypted, kek))

			digest = decrypted.read(MD5_DIGEST_LENGTH).hex()
			digest_calculated = md5(decrypted.read()).hexdigest()
			assert digest == digest_calculated

			decrypted.seek(MD5_DIGEST_LENGTH)
			length, = struct.unpack(">i", decrypted.read(INT_SIZE))

			ksb.value = decrypted.read(length)

			ksb.description = decrypted.read(ksb.info)

			return ksb

	def parse(filename, master_key=None):
		ksb = KeystoreBlob()
		with open(filename, "rb") as ksb.blob:
			ksb.parse_header()
			iv = ksb.blob.read(AES_BLOCK_SIZE)
			encrypted = ksb.blob.read()
			if (ksb.is_encrypted()):
				if master_key is None:
					print("The masterkey is required to decrypt this keystore blob")
					sys.exit(1)

				decrypted = BytesIO(ksb.decrypt(iv, encrypted, master_key))
				digest = decrypted.read(MD5_DIGEST_LENGTH).hex()
				digest_calculated = md5(decrypted.read()).hexdigest()
				assert digest == digest_calculated
			else:
				decrypted = BytesIO(encrypted)

			decrypted.seek(MD5_DIGEST_LENGTH)
			length, = struct.unpack(">i", decrypted.read(INT_SIZE))

			ksb.value = decrypted.read(length)

			ksb.description = decrypted.read(ksb.info)

			return ksb

	def parse_header(self):
		self.blob.seek(0, 2)
		self.blob_length = self.blob.tell()
		self.blob.seek(0)
		self.version, self.type, self.flags, self.info = self.blob.read(HEADER_SIZE)
		
	def generate_kek(self, password, salt):
		return pbkdf2_hmac(PBKDF2_ALGO, password, salt,
			KEK_ROUNDS, keylen=KEK_LENGTH)

	def decrypt(self, iv, encrypted, kek):
		return AES.new(kek, mode=AES.MODE_CBC, IV=iv).decrypt(encrypted)

	def is_encrypted(self):
		return (self.flags & KEYSTORE_FLAG_ENCRYPTED) == KEYSTORE_FLAG_ENCRYPTED

	def is_super_encrypted(self):
		return (self.flags & KEYSTORE_FLAG_SUPER_ENCRYPTED) == KEYSTORE_FLAG_SUPER_ENCRYPTED

def main():
	parser = argparse.ArgumentParser(description='Parse Android keystores')
	parser.add_argument('keyfile', help='user_X/uid_USRPKEY_keyname or just user_X/ to parse the whole directory')
	parser.add_argument('--master-key', help='user_X/.masterkey')
	parser.add_argument('--password', help='The password protecting the lockscreen')
	parser.add_argument('--dump-pem', action='store_true', help='Dump the decoded keys and certificates in <keyfile>.pem')

	args = parser.parse_args()
	if os.path.isdir(args.keyfile) and os.path.isfile(os.path.join(args.keyfile, '.masterkey')):
		args.master_key = os.path.join(args.keyfile, '.masterkey')

	mk_value = None
	if args.master_key:
		mk = KeystoreBlob.parse_master_key(args.master_key, args.password)
		mk_value = mk.value

	if os.path.isdir(args.keyfile):
		for kf in os.listdir(args.keyfile):
			if kf == '.masterkey': continue
			print("[+] Parsing %s" % kf)
			b = KeystoreBlob.parse(os.path.join(args.keyfile, kf), mk_value)
			if b.is_super_encrypted():
				print("This format is not supported.")
				continue

			KeystoreBlob.PRINTERS[b.type](b, os.path.join(args.keyfile, kf) + ".pem", args.dump_pem)
	else:	
		b = KeystoreBlob.parse(args.keyfile, mk_value)
		if b.is_super_encrypted():
			print("This format is not supported.")
			return
		KeystoreBlob.PRINTERS[b.type](b, args.keyfile + ".pem", args.dump_pem)

if __name__ == '__main__':
	main()
