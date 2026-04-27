CC = gcc

# macOS ships clang as gcc and uses ld64, so the linker flag differs from GNU ld
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  # macOS arm64 ld64 rejects -allow_stack_execute, so only disable the stack protector locally
  STACK_FLAGS = -fno-stack-protector
  OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
  CRYPTO_INC = -I$(OPENSSL_PREFIX)/include
  CRYPTO_LIB = -L$(OPENSSL_PREFIX)/lib -lcrypto
else
  STACK_FLAGS = -fno-stack-protector -z execstack
  CRYPTO_INC = -I/usr/include/openssl
  CRYPTO_LIB = -lcrypto
endif

CFLAGS = ${STACK_FLAGS} -Wall -Iutil -Iatm -Ibank -Irouter -I. ${CRYPTO_INC}

all: bin bin/atm bin/bank bin/init bin/router

bin:
	mkdir -p bin

bin/atm : atm/atm-main.c atm/atm.c util/crypto.c | bin
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c util/crypto.c -o bin/atm ${CRYPTO_LIB}

bin/bank : bank/bank-main.c bank/bank.c util/crypto.c | bin
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c util/crypto.c -o bin/bank ${CRYPTO_LIB}

bin/init : init.c util/crypto.c | bin
	${CC} ${CFLAGS} init.c util/crypto.c -o bin/init ${CRYPTO_LIB}

bin/router : router/router-main.c router/router.c | bin
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

clean:
	cd bin && rm -f *
