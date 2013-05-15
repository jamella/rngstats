
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

PROGRAMS := cipher-test dataset-test stats-serial

all: $(PROGRAMS)

cipher-test: cipher-test.o worker.o ciphertab.o $(CIPHERS)
	$(CC) $(CFLAGS) $^ -o $@

dataset-test: dataset-test.o dataset.o ciphertab.o $(CIPHERS)
	$(CC) $(CFLAGS) $^ -o $@ -lhdf5

stats-serial: stats-serial.o dataset.o worker.o ciphertab.o $(CIPHERS)
	$(CC) $(CFLAGS) $^ -o $@ -lhdf5


DATASET_H := dataset.h config.h
WORKER_H  := worker.h config.h

stats-serial.o cipher-test.o worker.o dataset.o: ciphers.h
ciphertab.o $(CIPHERS): ciphers.h
stats-serial.o cipher-test.o worker.o: $(WORKER_H)
stats-serial.o dataset.o dataset-test.o: $(DATASET_H)

ciphertab.c: gen-ciphertab $(CIPHERS.c)
	$(SHELL) gen-ciphertab ciphertab.c $(CIPHERS.c)

clean:
	-rm -f dataset.o worker.o ciphertab.o cipher-test.o dataset-test.o
	-rm -f stats-serial.o
	-rm -f $(CIPHERS)
	-rm -f $(PROGRAMS)
	-rm -f ciphertab.c

.PHONY: all clean
