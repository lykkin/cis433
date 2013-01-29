CC = gcc

all: uoenc uodec

uoenc: 
	gcc uoenc.c -lgcrypt -o enc

uodec: 
	gcc uodec.c -lgcrypt -o dec

clean: rm dec enc

cleantest: rm *.test.*
