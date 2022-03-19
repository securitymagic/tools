import re
#Used to decode malware from example https://app.any.run/tasks/b4f51d23-6346-478b-9b1a-4fd6970274a2/
#The version here is an example decoding used for a CTF I wrote in 2019
#Replace alphabet and encodedstring variables with your string samples
alphabet='''aKCCwqhCJrGjT}C7WfZ/N30@yeLlDFQbXPv-IViB14g{Opo=8HsM,k;dS' Rt:\(9mY6cnuE$A5x.'''
encodedstring="71;65;46;60;25;60;58;38;50;58;38;69;60;25;9;25;50;60;38;69;42;58;17;9;46;65;58;0;69;58;0;69;0;27;24;50;60;50;58;45;46;38;69;60;58;46;17;58;34;38;25;4;52;58;60;6;25;9;25;58;0;27;4;0;24;50;58;50;25;25;65;50;58;60;46;58;31;25;58;69;25;4;58;4;0;24;50;58;46;17;58;46;31;17;70;50;68;0;60;38;69;42;58;60;6;25;58;68;46;55;25;58;60;46;58;65;0;53;25;58;17;46;9;58;65;46;9;25;58;55;38;17;17;38;68;70;27;60;58;0;69;0;27;24;50;38;50;76;58;16;25;27;27;52;58;24;46;70;58;55;38;55;58;38;60;58;50;46;58;6;25;9;25;58;24;46;70;9;58;9;25;4;0;9;55;61;58;17;27;0;42;47;43;28;44;56;17;70;50;68;0;60;38;46;69;35;38;50;35;20;21;0;60;35;9;38;42;6;60;13"
encodedstring = re.sub(';', ' ', encodedstring) #remove single quotes
encodedstring = encodedstring.split(' ') #split the list

templist=list()

for p in encodedstring:
	v=int(p)
	if len(alphabet) > v:
		t = ''.join(alphabet[int(p)])
		templist.append(t)
	else:
		print ' '

print "Decoder has been run, Plaintext returned ", "\n"

print ''.join(templist).strip()
