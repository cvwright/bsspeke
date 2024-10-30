CC = cc
CFLAGS = -Wall

default: demo

lib: libbsspeke.a

monocypher.o: monocypher.c monocypher.h
	${CC} ${CFLAGS} -c monocypher.c -fPIC

bsspeke.o: bsspeke.c include/bsspeke.h monocypher.h
	${CC} ${CFLAGS} -c bsspeke.c -fPIC

libbsspeke.a: bsspeke.o monocypher.o
	ar rcs libbsspeke.a bsspeke.o monocypher.o

demo.o: demo.c include/bsspeke.h
	${CC} ${CFLAGS} -c demo.c -fPIC

demo: demo.o libbsspeke.a
	${CC} ${CFLAGS} -o demo demo.o -L. -lbsspeke -fPIC

clean:
	rm -f demo demo.o bsspeke.o monocypher.o libbsspeke.a
