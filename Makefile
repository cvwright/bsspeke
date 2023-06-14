default: demo

lib: libbsspeke.a

monocypher.o: monocypher.c monocypher.h
	cc -c monocypher.c -fPIC

bsspeke.o: bsspeke.c include/bsspeke.h monocypher.h
	cc -c bsspeke.c -fPIC

libbsspeke.a: bsspeke.o monocypher.o
	ar rcs libbsspeke.a bsspeke.o monocypher.o

demo.o: demo.c include/bsspeke.h
	cc -c demo.c -fPIC

demo: demo.o libbsspeke.a
	cc -o demo demo.o -L. -lbsspeke -fPIC

clean:
	rm -f demo demo.o bsspeke.o monocypher.o libbsspeke.a
