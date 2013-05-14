
CPPFLAGS := -I.

CFLAGS   := -g -O2 -std=c11 -pedantic -Wall -Wextra -Wbad-function-cast \
-Wchar-subscripts -Wcomment -Wfloat-equal -Wformat -Wmissing-declarations \
-Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wredundant-decls \
-Wstrict-aliasing -Wstrict-prototypes -Wswitch-enum -Wundef -Wwrite-strings

CIPHERS  := ciphers/aes.o \
            ciphers/arc4.o \
            ciphers/isaac64.o \
            ciphers/salsa20.o

all: selftest

selftest: main.o worker.o ciphertab.o $(CIPHERS)
	$(CC) $(CFLAGS) $^ -o $@

main.o worker.o ciphertab.o $(CIPHERS): ciphers.h
main.o worker.o: worker.h

ciphertab.c: gen-ciphertab $(CIPHERS:.o=.c)
	$(SHELL) gen-ciphertab ciphertab.c $(CIPHERS:.o=.c)
