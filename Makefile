
OPTIMIZATION ?= -O2
STDFLAGS ?= -std=c99
DEBUGFLAGS ?= -Waggregate-return -Wcast-align -Wcast-qual \
-Wchar-subscripts -Wcomment -Wimplicit -Wmissing-declarations \
-Wmissing-prototypes -Wnested-externs -Wparentheses -Wwrite-strings \
-Wformat=2 -Wall -Wextra

CFLAGS ?= $(OPTIMIZATION) $(STDFLAGS) $(DEBUGFLAGS)

all: dnsblast

dnsblast: Makefile dnsblast.o
	$(CC) dnsblast.o -o dnsblast $(LDFLAGS)

dnsblast.o: Makefile dnsblast.c dns.h dnsblast.h
	$(CC) -c dnsblast.c -o dnsblast.o $(CFLAGS)

clean:
	rm -f dnsblast *.a *.d *.o
	rm -rf *.dSYM
