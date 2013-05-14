
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

PROGRAMS := selftest stats-serial

all: $(PROGRAMS)

selftest: selftest.o worker.o ciphertab.o $(CIPHERS)
	$(CC) $(CFLAGS) $^ -o $@

stats-serial: stats-serial.o dataset.o worker.o ciphertab.o $(CIPHERS)
	$(CC) $(CFLAGS) $^ -o $@

stats-serial.o selftest.o worker.o ciphertab.o $(CIPHERS): ciphers.h
stats-serial.o selftest.o worker.o: worker.h
stats-serial.o dataset.o: dataset.h

ciphertab.c: gen-ciphertab $(CIPHERS.c)
	$(SHELL) gen-ciphertab ciphertab.c $(CIPHERS.c)

clean:
	-rm -f selftest.o worker.o ciphertab.o $(CIPHERS)
	-rm -f $(PROGRAMS)
	-rm -f ciphertab.c

.PHONY: all clean
