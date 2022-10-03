tmp.h: ../include/bsspeke.h
	grep -v ^\#include ../include/bsspeke.h > tmp.h

headers: tmp.h
	mkdir -p include
	$(CPP) -I .. -o include/bsspeke.h tmp.h
