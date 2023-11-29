CFLAGS = -Wall -Wextra -O2 -march=native -s
SHA_224_INCLUDE = -I./sha-224
SHA_256_INCLUDE = -I./sha-256
SHA_224_LIB = ./sha-224/sha-224.c
SHA_256_LIB = ./sha-256/sha-256.c
TEST = test

all:
	${CC} ${CFLAGS} ${SHA_224_INCLUDE} tests/${TEST}-224.c ${SHA_224_LIB} -o ${TEST}-224
	${CC} ${CFLAGS} ${SHA_256_INCLUDE} tests/${TEST}-256.c ${SHA_256_LIB} -o ${TEST}-256

clean:
	rm -f ${TEST}-224 ${TEST}-256
