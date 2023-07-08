#This script Extracts solarmarker reflective DLL from current malware dropper campaign (started May 2023)
#Example Installer: 01eee7bbd593b75684234d51530a87c1
#By Lucas Acha (www.lukeacha.com)
#Version 1.1
#To-Do: Add Argparse, properly resolve extra 16 byte addition after decryption
#July 78, 2023

import base64  ,re
from Crypto.Cipher import AES

#Regular Expressions to find base64 encodings and AES key/IV
b64find = re.compile('J([A-Za-z0-9+=]{1000,})', re.MULTILINE)
aeskeyfind = re.compile('](\d{1,3}\,){31}\d{1,3}\)')
aesivfind = re.compile('](\d{1,3}\,){15}\d{1,3}\)')
aesb64find = re.compile('([A-Za-z0-9+=/]{1000,})', re.MULTILINE)

#open malware installer/dropper
ifile = open("solarmarker.malz",'r+b')
# Read file object to string
text = ifile.read()
#close file after its contents read into a variable string
ifile.close()

#create new file for the extracted dll
f = open("solarmarker.dll", "wb")

aeskey = ''
aesiv = ''
t = []
l = ''
decodedb64 = ''

#Remove Null Bytes from file
for x in text:
    if not x == 0:
        t.append(chr(x))
l = ''.join(t)

#Match on Embeeded Base64 in File
for x in b64find.finditer(l):
    t = x.group()
#Decode Base64: Once this is done we will have the Powershell script that runs the Reflective DLL
    try:
         decodedb64 = base64.b64decode(t)
    except:
        pass

#Convert Base64 into UTF8 for use in matching data in the powershell script
s = decodedb64.decode('utf-8')

#Match and clean AES Key
for x in aeskeyfind.finditer(s):
    aeskey = x.group()
    aeskey = aeskey.lstrip(']')
    aeskey = aeskey.rstrip(')')

#Match and clean AES IV
for x in aesivfind.finditer(s):
    aesiv = x.group()
    aesiv = aesiv.lstrip(']')
    aesiv = aesiv.rstrip(')')

#Match Ciphertext from Powershell Script
aesb64 =''
for x in aesb64find.finditer(s):
    aesb64 = x.group()

#Base64 decode Ciphertext into byte data for later use
enc = base64.b64decode(aesb64)

aesiv = aesiv.split(',')
aeskey = aeskey.split(',')
aesiv2 = []
aeskey2 = []

#Convert AES IV into bytes
for x in aesiv:
  t = int(x)
  aesiv2.append(t.to_bytes(1,'big'))

#Convert AES Key into bytes
for x in aeskey:
  t = int(x)
  aeskey2.append(t.to_bytes(1,'big'))

#Join Key/IV into byte string (cannot use list for AES process)
aeskey2= b''.join(aeskey2)
aesiv2 = b''.join(aesiv2)
iv = aesiv2
key = aeskey2

#Create Decryption routine
cipher = AES.new(key, AES.MODE_CBC, iv)
smdecode = cipher.decrypt(enc)

#Remove trailing 16 bytes, not sure why this gets added, will troubleshoot in the future
smdecode = smdecode[:-16]

#Write DLL file
f.write(smdecode)
