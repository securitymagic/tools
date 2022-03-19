import re
#Based on example: https://maxkersten.nl/binary-analysis-course/analysis-scripts/automatic-string-formatting-deobfuscation/
#Initially Used for various malware decoding (ie. Emotet)
#Current example is setup to decode a CTF I wrote in 2019
flagindex="{7}{18}{30}{104}{34}{75}{101}{12}{64}{68}{63}{45}{39}{0}{13}{4}{28}{47}{41}{78}{32}{36}{88}{10}{37}{19}{97}{11}{55}{73}{53}{82}{20}{57}{103}{33}{56}{29}{74}{96}{14}{102}{112}{35}{9}{16}{54}{66}{70}{2}{69}{15}{24}{25}{65}{93}{43}{111}{86}{109}{76}{42}{71}{99}{80}{91}{49}{51}{59}{26}{79}{46}{22}{90}{106}{95}{77}{21}{31}{67}{84}{50}{110}{107}{52}{48}{23}{83}{92}{81}{58}{3}{60}{72}{61}{44}{100}{17}{8}{94}{62}{38}{1}{89}{85}{87}{27}{108}{105}{5}{98}{6}{40}"
flaglist=['n cr', 'imply', 't', ' that', 'ed th', ' v', 'd te', 'To', 'es ', 'ordere', 'it in', 'dom c', 't we', 'eat', 'd ', 'could ', 'd', 'one do', ' enc', 'list ', ' ran', 'in', '={', 'e', 'be', ' put b', 'd', 'o de', 'is tex', 'ed ', 'ode t', '-P', ' then', 'rran', 'halle', ' ', ' we s', 'to a ', ' s', 'the', 'xt.', 'ing', 'se64 ', 'the', 'ensur', ' ', 'lag', 't str', 'm', 'raw c', 'ist', 'omp', 'ow so', 'sizes', ' it', 'h', 'g', 'doml', '-sense', 'resse', ' i', 'd to ', 't just', 'ython,', ' ', 'ack t', ' so', 'y', 'used P', ' it ', ' tha', 'the t', 's use', 'unck ', 'that l', 'nge,', ' we ba', 'mnes$-', ', and', ' it: f', 't ', ' non', ', then', ' fill', 'thon-L', 'ry', ', f', ' t', 'plit ', ' t', 'R@', 'and ', 'er', 'oge', 'no', '0', 'ist an', 'of ran', 'ery en', 'ex', 'e some', ' firs', 't', 'y rea', 'his c', 'he', 'nd', 'nd n', 'code t', 'inally', '} a', 'r', 'hen']
flagindex = re.sub('{', '', flagindex) #remove leading bracket
flagindex = re.sub('}', ' ', flagindex) #remove trailing bracket while maintaining space between numbers
#print flagindex
flagindex = flagindex.split() #split the list
templist=list()
print flagindex

for p in flagindex:
	v = ''.join(flaglist[int(p)]) #convert line item to integer to use as index for evilstring
	templist.append(v) #store results in new list
print ''.join(templist).strip()
