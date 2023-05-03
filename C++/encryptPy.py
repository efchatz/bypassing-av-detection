#python3 
#pip install crypto, pycryptodome
import sys
from Crypto.Cipher import AES
from secrets import token_bytes
from binascii import unhexlify
import hashlib

KEY = token_bytes(16)

def pad(s):
    padding_length = AES.block_size - len(s) % AES.block_size
    padding = bytes([padding_length] * padding_length)
    return s + padding

def aesenc(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = bytes(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    return ciphertext

def aesdec(ciphertext, key):
    k = hashlib.sha256(key).digest()
    iv = bytes(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(bytes([plaintext[-1]]))
    
#Comment file encryption relevant code and uncomment
#the hex code to encrypt a shellcode, instead of a file
try:
    #hex_payload = sys.argv[1].strip()
    #plaintext = unhexlify(hex_payload)
    with open(sys.argv[1], "rb") as f:
        plaintext = f.read()
except:
    #print("Invalid hex string!")
    print("File needed!")
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
open("file_sliv.ico", "wb").write(ciphertext)
#print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
#decryption
#decrypted_plaintext = aesdec(ciphertext, KEY)
#print('Decrypted plaintext{ 0x' + ', 0x'.join(hex(x)[2:] for x in decrypted_plaintext) + ' };')
