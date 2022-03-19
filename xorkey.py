#Multibyte XOR encoder/Decoder By Lucas Acha
#This scripts works with a known XOR key
#For multibye text based key
#xorkey.py  -k <Known ASCII key like ThisIsMyKey> -f <input file> -o <output file>
#
#For a single byte known hex key
#xorkey.py  -h 0xhh -f <input file> -o <output file>

import argparse

encodekey=""
filename = ""
outfile=""
keycode = 0

def encoderdecoder():
	global encodekey, filename, outfile
	keylength = len(encodekey) -1
	print 'Key Length is ', keylength
	print 'Input File is ',filename
	print 'Output File is ', outfile
	counter = 0
	encodekey = ",".join("{:02x}".format(ord(c)) for c in encodekey)
	encodekey = encodekey.split(",")
	addstring = "0x"
	encodekey = [addstring + x for x in encodekey]
	newlist = []
	for i in encodekey:
		i = int(i,16)
		newlist.append(i)

	b = bytearray(open(filename, 'rb').read())
	for i in range(len(b)):
		b[i] ^= newlist[counter]
		counter += 1
		if counter > keylength:
			counter = 0
		
	open(outfile, 'wb').write(b)
	print 'Operation is Complete, check output file ', outfile

def encoderdecoderhex():
	global encodekey, filename, outfile
	print 'Input File is ',filename
	print 'Output File is ', outfile
	newlist =[]
	newlist.append(int(encodekey,16))
	b = bytearray(open(filename, 'rb').read())
	for i in range(len(b)):
		b[i] ^= newlist[0]
			
	open(outfile, 'wb').write(b)
	print 'Operation is Complete, check output file ', outfile

#Command Line Switches
def Main():
	global args, encodekey, filename, outfile, keycode
	parser = argparse.ArgumentParser()
	parser.add_argument('-f','--file', help='input file')
	parser.add_argument('-k','--key', help='specify key')
	parser.add_argument('-o','--out', help='specify output file')
	parser.add_argument('-e','--hex', help='specify 1 byte key in hex format 0xHH')
	args = vars(parser.parse_args())
	if args['file']:
		filename = args['file']
	if args['key']:
		encodekey = args['key']
		keycode = keycode +1
		#print keycode
	if args['out']:
		outfile = args['out']
	if args['hex']:
		encodekey=args['hex']
		keycode = keycode + 2
		#print keycode
	if keycode == 1:
		encoderdecoder()
	if keycode == 2:
		encoderdecoderhex()
	if keycode == 3 or keycode == 0:
		print 'You must specificy a keycode either -k <ascii text> or -h 0xhh, you cannot use both'
			
if __name__ == '__main__':
    Main()
