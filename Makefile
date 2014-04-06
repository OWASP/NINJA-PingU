PLUGINS=Simple Service
PSOURCE=scanner.c
POBJECT=$(PSOURCE:.c=.o)
PLIB=$(PSOURCE:.c=.so)
CC=gcc
CFLAGS=-Wall -O3 -fstack-protector-all -Wwrite-strings -Wunreachable-code -Wpointer-arith  -Wcast-qual -falign-functions=4 -falign-jumps -Wint-to-pointer-cast -Wno-pointer-to-int-cast
LDFLAGS=-fPIC -ldl -lpthread
CPFLAGS=-O3 -Wall -fstack-protector-all -falign-jumps
SYFLAGS= -pedantic -Wall -std=c99 -fpic -I.
SFLAGS=-shared
PLUGSRC=src/plugin

.PHONY: all clean npingu

all: $(PLUGINS) npingu

 npingu: src/npingu.c
	$(CC) $(CFLAGS) src/npingu.c -o bin/npingu $(LDFLAGS)

 $(PLUGINS):
	$(CC) $(CPFLAGS) -c $(PLUGSRC)/$@/$(PSOURCE) -o $(PLUGSRC)/$@/$(POBJECT) $(SYFLAGS)
	$(CC) -o $(PLUGSRC)/$@/$(PLIB) $(PLUGSRC)/$@/$(POBJECT) $(SFLAGS)

 profile:
	$(CC) -c $(PLUGSRC)/Service/$(PSOURCE) -o $(PLUGSRC)/Service/$(POBJECT) $(SYFLAGS) -g
	$(CC) -o $(PLUGSRC)/Service/$(PLIB) $(PLUGSRC)/Service/$(POBJECT) $(SFLAGS)
	$(CC) $(CFLAGS) -g -o bin/npingu src/npingu.c $(LDFLAGS) -pg


