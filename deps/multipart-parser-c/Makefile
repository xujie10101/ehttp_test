CFLAGS?=-std=c89 -ansi -pedantic -O4 -Wall -fPIC 

CC?=gcc

default: multipart_parser.o

multipart_parser.o: multipart_parser.c multipart_parser.h

solib: multipart_parser.o
	$(CC) -shared -Wl,-soname,libmultipart.so -o libmultipart.so multipart_parser.o

alib: multipart_parser.o
	ar -rcs libmultipart.a multipart_parser.o
clean:
	rm -f *.o *.so
