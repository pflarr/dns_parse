build: dns_parse

install:
	cp dns_parse ${DESTDIR}/bin/

src_tar:
	mkdir dns_parse-${version}
	cp *.c *.h Makefile dns_parse-${version}/
	tar -czf dns_parse-${version}.tar.gz dns_parse-${version}

dns_parse: dns_parse.c rtypes.o strutils.o
	gcc -lpcap rtypes.o strutils.o -o bin/dns_parse dns_parse.c

rtypes.o: rtypes.c rtypes.h
	gcc -c rtypes.c

strutils.o: strutils.h strutils.c
	gcc -c strutils.c

clean:
	rm -f *.o
	rm -rf bin dns_parse-*

test_strutils: strutils.c
	gcc -o bin/test_strutils strutils.c
	./bin/test_strutils
