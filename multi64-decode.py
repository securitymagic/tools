import sys, getopt, base64
#Written By Luke Acha (www.lukeacha.com)
#This tool was originally written to solve CTFs
#Use this tool to look for known plaintext that has been Base64 encoded multiple times
#Example: Search for "GIF89a", "flag" or maybe something like "DOS mode"
#Usage: python multi64-decode.py -i <file name>
#Enter number of iterations you want to try (maybe 30 or higher for CTF)
#Enter plaintext you expect to find
#Use -o <output file name> to send successful result to a file
def decodeme():
	global inputfile, arg, f, result
	inputfile = arg
	f = open(inputfile, 'rb')
	data = f.read()
	x = input("enter number of base64 interations: ")
	header = raw_input("enter known header text to search for: ")
	p=0
	try:
		result = base64.b64decode(data)
		for i in range(int(x)):
			if not str(header) in result: #if you have known text
				p = p + 1
				result = base64.b64decode(result)
			#print result
	except:
		print 'Failed'
	if header in result:	
		print result
		print "\n Number of iterations where result found: " + str(p)
		print "\n Found with searching the plain text of: " + str(header)
	else:
		print "No decoded text matching known header found"
	return

def main(argv):
   global inputfile, arg, f, result, decodeme
   inputfile = ''
   outputfile = ''
   try:
      opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
   except getopt.GetoptError:
      print 'test.py -i <inputfile> -o <outputfile> OR instead of -o use-p to print result to terminal'
      sys.exit(2)
   for opt, arg in opts:
	   if opt == '-h':
		   print 'test.py -i <inputfile> -o <outputfile>'
		   sys.exit()
	   elif opt in ("-i", "--ifile"):
		   decodeme()
	   elif opt in ("-o", "--ofile"):
		   outputfile = arg
		   fo = open(outputfile, 'w')
		   print >> fo, result
		   fo.close()
 
if __name__ == "__main__":
   main(sys.argv[1:])
