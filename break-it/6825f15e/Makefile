CC ?= gcc
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)

ifeq ($(shell uname),Darwin)
  STACK_FLAGS = -fno-stack-protector
else
  STACK_FLAGS = -fno-stack-protector -z execstack
endif

CFLAGS = ${STACK_FLAGS} -Wall -Iutil -Iatm -Ibank -Irouter -I.
ifneq ($(OPENSSL_PREFIX),)
  OPENSSL_FLAGS ?= -I$(OPENSSL_PREFIX)/include
  OPENSSL_LIBS ?= -L$(OPENSSL_PREFIX)/lib
endif
LDLIBS = $(OPENSSL_LIBS) -lcrypto

all: bin bin/atm bin/bank bin/init bin/router

bin:
	mkdir -p bin

bin/atm : atm/atm-main.c atm/atm.c util/security.c
	${CC} ${CFLAGS} ${OPENSSL_FLAGS} util/security.c atm/atm.c atm/atm-main.c -o bin/atm ${LDLIBS}

bin/bank : bank/bank-main.c bank/bank.c util/security.c
	${CC} ${CFLAGS} ${OPENSSL_FLAGS} util/security.c bank/bank.c bank/bank-main.c -o bin/bank ${LDLIBS}

bin/init : init/init-main.c util/security.c
	${CC} ${CFLAGS} ${OPENSSL_FLAGS} util/security.c init/init-main.c -o bin/init ${LDLIBS}

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

clean:
	mkdir -p bin
	rm -f bin/*
