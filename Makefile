CC = gcc

ifeq ($(CC),clang)
  STACK_FLAGS = -fno-stack-protector -Wl,-allow_stack_execute
else
  STACK_FLAGS = -fno-stack-protector -z execstack
endif

CFLAGS = ${STACK_FLAGS} -Wall -Iutil -Iatm -Ibank -Irouter -I.

all: bin bin/atm bin/bank bin/init bin/router

bin:
	mkdir -p bin

bin/atm : atm/atm-main.c atm/atm.c | bin
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c -o bin/atm

bin/bank : bank/bank-main.c bank/bank.c | bin
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c -o bin/bank

bin/init : init.c | bin
	${CC} ${CFLAGS} init.c -o bin/init

bin/router : router/router-main.c router/router.c | bin
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

clean:
	cd bin && rm -f *
