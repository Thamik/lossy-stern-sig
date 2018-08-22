# project: lossy-stern3-sig
# Makefile created by Dominik Leichtle
# modified on Wed, 2017-12-13

CC = gcc
CFLAGS = -Wall -c
LFLAGS = -Wall -lm
OBJ = main.o lossy-stern3-sig.o
LINKOBJ = $(OBJ) cpucycles-20060326/cpucycles.o
NISTAPIOBJ = lossy-stern3-sig.o rng.o api.o PQCgenKAT_sign.o
BIN = main_debug main_release PQCgenKAT_sign
LIBS = -L/usr/lib -L./KeccakCodePackage-master/bin/generic64 -lssl -lcrypto -lkeccak

debug: CFLAGS += -g -O0
debug: LFLAGS += -g -O0 -lm
release: CFLAGS += -O3
release: LFLAGS += -O3 -flto
nist_api: CFLAGS += -O3 -DNIST_API
nist_api: LFLAGS += -O3 -flto

all: keccak cpucycles release

debug: $(OBJ) sig.h
	$(CC) -o main_debug $(LINKOBJ) $(LIBS) $(LFLAGS)

release: $(OBJ) sig.h
	$(CC) -o main_release $(LINKOBJ) $(LIBS) $(LFLAGS)

nist_api: $(NISTAPIOBJ) sig.h
	$(CC) -o PQCgenKAT_sign $(NISTAPIOBJ) $(LIBS) $(LFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -o main.o main.c

lossy-stern3-sig.o: lossy-stern3-sig.c
	$(CC) $(CFLAGS) -o lossy-stern3-sig.o lossy-stern3-sig.c

rng.o: rng.c
	$(CC) $(CFLAGS) -o rng.o rng.c

api.o: api.c
	$(CC) $(CFLAGS) -o api.o api.c

PQCgenKAT_sign.o: PQCgenKAT_sign.c
	$(CC) $(CFLAGS) -o PQCgenKAT_sign.o PQCgenKAT_sign.c

keccak:
	make -C KeccakCodePackage-master generic64/libkeccak.a

cpucycles:
	cd cpucycles-20060326; \
	sh do; \
	cd ..

.PHONY: clean clean_keccak clean_cupcycles clean_all

clean_all: clean clean_keccak clean_cupcycles

clean:
	rm -f $(OBJ) $(BIN) $(NISTAPIOBJ)

clean_keccak:
	make -C KeccakCodePackage-master clean

clean_cupcycles:
	rm -f cpucycles-20060326/cpucycles.o cpucycles-20060326/cpucycles.h
