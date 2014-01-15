 all: clean npingu

 npingu: src/npingu.c
	gcc -c src/plugin/Service/scanner.c -o src/plugin/Service/scanner.o -pedantic -g -Wall -std=c99 -fpic -I.
	gcc -o src/plugin/Service/scanner.so src/plugin/Service/scanner.o -shared
	gcc -c src/plugin/Simple/scanner.c -o src/plugin/Simple/scanner.o -pedantic -g -Wall -std=c99 -fpic -I.
	gcc -o src/plugin/Simple/scanner.so src/plugin/Simple/scanner.o -shared
	gcc -O3 -g -ldl -Wall -Wwrite-strings -Wunreachable-code -Wpointer-arith  -Wcast-qual -falign-functions=4 -falign-jumps -Wint-to-pointer-cast -Wno-pointer-to-int-cast -lpthread -o bin/npingu src/npingu.c

 clean:
	rm bin/npingu

