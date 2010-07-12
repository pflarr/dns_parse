build: pcap_test

pcap_test: pcap_test.c rtypes.o strutils.o
	gcc -lpcap  rtypes.o strutils.o -o pcap_test pcap_test.c
	./pcap_test

rtypes.o: rtypes.c rtypes.h
	gcc -c rtypes.c

strutils.o: strutils.h strutils.c
	gcc -c strutils.c

clean:
	rm -f *.o
	rm -f pcap_test test_strutils

test_strutils: strutils.c
	gcc -o test_strutils strutils.c
	./test_strutils
	
