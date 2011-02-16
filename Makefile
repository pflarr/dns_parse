build: bin/dns_parse

install:
	mkdir -p ${DESTDIR}/usr/local/sbin/
	cp bin/* ${DESTDIR}/usr/local/sbin/
	mkdir -p ${DESTDIR}/etc/init.d/
	cp init/dnscapture ${DESTDIR}/etc/init.d/
	cp etc/* ${DESTDIR}/etc/
	
tar: clean
	if [ -z ${version} ]; then \
		echo "set 'version' env variable first."; \
		false;\
	fi;
	mkdir dns_parse-${version}
	cp -r *.c *.h bin etc init Makefile dns_parse-${version}/
	tar -czf dns_parse-${version}.tar.gz dns_parse-${version}
	rm -rf dns_parse-${version}

bin/dns_parse: dns_parse.c rtypes.o strutils.o
	mkdir -p bin
	gcc -lpcap rtypes.o strutils.o -o bin/dns_parse dns_parse.c

rtypes.o: rtypes.c rtypes.h
	gcc -g -c rtypes.c

strutils.o: strutils.h strutils.c
	gcc -g -c strutils.c

clean:
	rm -f *.o
	rm -rf bin/dns_parse dns_parse-*

test_strutils: strutils.c
	mkdir bin
	gcc -o bin/test_strutils strutils.c
	./bin/test_strutils
