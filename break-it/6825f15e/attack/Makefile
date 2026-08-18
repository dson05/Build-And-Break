CC ?= gcc
CFLAGS ?= -Wall -I.. -I../router -I../util -I.

all: ../bin/router

../bin/router: router-main.c ../router/router.c ../router/router.h ../ports.h
	$(CC) $(CFLAGS) router-main.c ../router/router.c -o ../bin/router

clean:
	rm -f ../bin/router

restore:
	cd .. && $(MAKE) bin/router
