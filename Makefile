all:			apmislay-lib.o client-example server-example

client-example:		client-example.c apmislay.h apmislay-lib.c
			gcc -g3 -Wall -O2 client-example.c apmislay-lib.o -lpcap -o client-example

server-example:		server-example.c apmislay.h apmislay-lib.c
			gcc -g3 -Wall -O2 server-example.c apmislay-lib.o -lpcap -o server-example

apmislay-lib.o:		apmislay-lib.c apmislay.h
			gcc -g3 -c -O2 -Wall apmislay-lib.c
			@echo "you could link apmislay-lib.o how client-example and server-exmple"

clean:
			rm -rf *.o client-example server-example
