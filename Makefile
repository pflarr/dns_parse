build: pcap_test

pcap_test: pcap_test.c rtypes.o rtypebase.o
	gcc -L. -lpcap  rtypes.o rtypebase.o -o pcap_test pcap_test.c

rtypes.o: rtypes.c rtypes.h
	gcc -c rtypes.c

rtypebase.o: rtypebase.c rtypebase.h
	gcc -c rtypebase.c

clean:
	rm -f *.o
	rm -f pcap_test test_strutils
