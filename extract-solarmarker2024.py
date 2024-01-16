#Extracts solarmarker DLL from current malware dropper campaign (started Jan 2024)
#Example Installer: 88be786a58b74ecf50f88e9175705d80
#By Lucas Acha
#Version 1.1
#January 16, 2024

import base64, re, argparse
from Crypto.Cipher import AES

#Regular Expressions to find base64 encodings and AES key/IV
b64find = re.compile('([A-Za-z0-9+=/]{1000,})', re.MULTILINE)
aeskeyfind = re.compile('](\d{1,3}\,){31}\d{1,3}\)')
aesivfind = re.compile('](\d{1,3}\,){15}\d{1,3}\)')

#variables:
aeskey = ''
aesiv = ''
t = []
l = ''
decodedb64 = ''
dllfile = 'solarmarker.dll'
smfile = 'solarmarker.malz'

parser = argparse.ArgumentParser()
parser.add_argument('-f','--file', help='read input sample file -f <file.csv>')
args = vars(parser.parse_args())
#Command Line Branches	
if args['file']:
    smfile = args['file']

#open file
try:
    ifile = open(smfile, 'rb')
except:
    print('Require input file: -f <filename>')
    exit()
# Read file object to string
text = ifile.read()
#close file after its contents read into a variable string
ifile.close()

f = open(dllfile, "wb")
  
for x in text:
    t.append(chr(x))
l = ''.join(t)

for x in b64find.finditer(l):
    t = x.group()
#Decode Base64: Once this is done we will have the Powershell script that runs the Reflective DLL
    try:
         decodedb64 = base64.b64decode(t)
    except:
        pass

#Match and clean AES Key
for x in aeskeyfind.finditer(l):
    aeskey = x.group()
    aeskey = aeskey.lstrip(']')
    aeskey = aeskey.rstrip(')')

#Match and clean AES IV
for x in aesivfind.finditer(l):
    aesiv = x.group()
    aesiv = aesiv.lstrip(']')
    aesiv = aesiv.rstrip(')')

#print(aesiv)
#print(aeskey)

#Match Ciphertext from Powershell Script
aesb64 =''

#Base64 decode Ciphertext into byte data for later use
enc = decodedb64
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
f.close()
