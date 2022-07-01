from banner.banner import *
import argparse
import hashlib
from beautifultable import BeautifulTable
import time

parse = argparse.ArgumentParser()
########## List of supported hashes
parse.add_argument("--hashes",help="Hashes supported",action='store_true')
########## hash --> MD5
parse.add_argument("--md5",help="MD5 hash")
########## hash --> SHA-1
parse.add_argument("--sha1",help="SHA-1 hash")
########## hash --> SHA-224
parse.add_argument("--sha224",help="SHA-224 hash")
########## hash --> SHA-256
parse.add_argument("--sha256",help="SHA-256 hash")
########## hash --> SHA-384
parse.add_argument("--sha384",help="SHA-384 hash")
########## hash --> SHA-512
parse.add_argument("--sha512",help="SHA-512 hash")
########## hash --> SHA3-224
parse.add_argument("--sha3_224","--sha3-224",help="SHA3-224 hash")
########## hash --> SHA3-256
parse.add_argument("--sha3_256","--sha3-256",help="SHA3-256 hash")
########## hash --> SHA3-384
parse.add_argument("--sha3_384","--sha3-384",help="SHA3-384 hash")
########## hash --> SHA3-512
parse.add_argument("--sha3_512","--sha3-512",help="SHA3-512 hash")
########## Wordlist
parse.add_argument("-w","--wordlist",help="Wordlist", required=True)
parse.add_argument("-o", "--output",default="stdout",required=False, dest='output', help="Directs the output to a name of your choice")
parse = parse.parse_args()

def hashesSupported():
	table = BeautifulTable()
	table.columns.header = [f"{RED_NORMAL}HASH{END}", f"{GREEN_NORMAL}COMMAND{END}"]
	table.rows.append(["MD5", "--md5"])
	table.rows.append(["SHA-1", "--sha1"])
	table.rows.append(["SHA-224", "--sha224"])
	table.rows.append(["SHA-256", "--sha256"])
	table.rows.append(["SHA-384", "--sha384"])
	table.rows.append(["SHA-512", "--sha512"])
	table.rows.append(["SHA3-224", "--sha3-224"])
	table.rows.append(["SHA3-256", "--sha3-256"])
	table.rows.append(["SHA3-384", "--sha3-384"])
	table.rows.append(["SHA3-512", "--sha3-512"])
	print(table)

try:
	pass_file = open(parse.wordlist,"r")

except:
	pass

f = open(parse.output, "a", encoding='utf-8')	

def crackMD5():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.md5(enc.strip()).hexdigest()

		if parse.md5 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["MD5", hashe, password])
			print(table)
			f.write("HASH: MD5\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA1():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha1(enc.strip()).hexdigest()

		if parse.sha1 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA-1", hashe, password])
			print(table)
			f.write("HASH: SHA-1\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA224():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha224(enc.strip()).hexdigest()

		if parse.sha224 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA-224", hashe, password])
			print(table)
			f.write("HASH: SHA-224\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA256():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha256(enc.strip()).hexdigest()

		if parse.sha256 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA-256", hashe, password])
			print(table)
			f.write("HASH: SHA-256\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA384():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha384(enc.strip()).hexdigest()

		if parse.sha384 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA-384", hashe, password])
			print(table)
			f.write("HASH: SHA-384\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break


def crackSHA512():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha512(enc.strip()).hexdigest()

		if parse.sha512 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA-512", hashe, password])
			print(table)
			f.write("HASH: SHA-512\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA3_224():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha3_224(enc.strip()).hexdigest()

		if parse.sha3_224 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA3-224", hashe, password])
			print(table)
			f.write("HASH: SHA3-224\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA3_256():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha3_256(enc.strip()).hexdigest()

		if parse.sha3_256 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA3-256", hashe, password])
			print(table)
			f.write("HASH: SHA3-256\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA3_384():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha3_384(enc.strip()).hexdigest()

		if parse.sha3_384 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA3-384", hashe, password])
			print(table)
			f.write("HASH: SHA3-384\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break

def crackSHA3_512():
	for password in pass_file:
		password = password.replace("\n","")
		enc = password.encode('utf-8')
		hashe = hashlib.sha3_512(enc.strip()).hexdigest()

		if parse.sha3_512 == hashe:
			table = BeautifulTable()
			table.columns.header = [f"{WHITE}HASH{END}", f"{RED_NORMAL}ENCRYPTED{END}", f"{GREEN_NORMAL}DECRYPTED{END}"]
			table.rows.append(["SHA3-384", hashe, password])
			print(table)
			f.write("HASH: SHA3-512\nENCRYPTED: {}\nDECRYPTED: {}".format(hashe,password)+'\n'+'\n')
			f.close()
			break								


def main():
	if parse.hashes:
		hashesSupported()

	elif parse.md5:
		crackMD5()

	elif parse.sha1:
		crackSHA1()

	elif parse.sha224:
		crackSHA224()

	elif parse.sha256:
		crackSHA256()

	elif parse.sha384:
		crackSHA384()

	elif parse.sha512:
		crackSHA512()

	elif parse.sha3_224:
		crackSHA3_224()

	elif parse.sha3_256:
		crackSHA3_256()

	elif parse.sha3_384:
		crackSHA3_384()

	elif parse.sha3_512:
		crackSHA3_512()						 	

	else:
		print(f"{RED_NORMAL}[ERR0R]{END} Argument invalid\nRequest help : python3 hashcrack.py --help\nExit the script...")
		time.sleep(2)
		exit(0)




if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		exit()	