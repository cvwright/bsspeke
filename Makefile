default: demo

lib: libbsspeke.a

minimonocypher.o: minimonocypher.c minimonocypher.h
	cc -c minimonocypher.c -fPIC

bsspeke.o: bsspeke.c include/bsspeke.h minimonocypher.h
	cc -c bsspeke.c -fPIC

demo.o: demo.c include/bsspeke.h
	cc -c demo.c -fPIC

demo: demo.o libbsspeke.a
	cc -o demo demo.o -L. -lbsspeke -fPIC

libbsspeke.a: bsspeke.o minimonocypher.o
	ar rcs libbsspeke.a bsspeke.o minimonocypher.o

clean:
	rm -f demo demo.o bsspeke.o minimonocypher.o libbsspeke.a
