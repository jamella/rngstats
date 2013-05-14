
CPPFLAGS := -I.

CFLAGS   := -g -O2 -std=c11 -pedantic -Wall -Wextra -Wbad-function-cast \
-Wchar-subscripts -Wcomment -Wfloat-equal -Wformat -Wmissing-declarations \
-Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wredundant-decls \
-Wstrict-aliasing -Wstrict-prototypes -Wswitch-enum -Wundef -Wwrite-strings

CIPHERS  := ciphers/aes.o \
            ciphers/arc4.o \
            ciphers/isaac64.o \
            ciphers/salsa20.o
CIPHERS.c := $(CIPHERS:.o=.c)

PROGRAMS := selftest

all: $(PROGRAMS)

selftest: selftest.o worker.o ciphertab.o $(CIPHERS)
	$(CC) $(CFLAGS) $^ -o $@

selftest.o worker.o ciphertab.o $(CIPHERS): ciphers.h
selftest.o worker.o: worker.h

ciphertab.c: gen-ciphertab $(CIPHERS.c)
	$(SHELL) gen-ciphertab ciphertab.c $(CIPHERS.c)

clean:
	-rm -f selftest.o worker.o ciphertab.o $(CIPHERS)
	-rm -f $(PROGRAMS)
	-rm -f ciphertab.c

.PHONY: all clean
