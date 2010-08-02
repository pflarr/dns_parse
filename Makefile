build: dns_parse

dns_parse: dns_parse.c rtypes.o strutils.o
	gcc -lpcap  rtypes.o strutils.o -o dns_parse dns_parse.c
	./dns_parse

rtypes.o: rtypes.c rtypes.h
	gcc -c rtypes.c

strutils.o: strutils.h strutils.c
	gcc -c strutils.c

clean:
	rm -f *.o
	rm -f dns_parse test_strutils

test_strutils: strutils.c
	gcc -o test_strutils strutils.c
	./test_strutils
	
