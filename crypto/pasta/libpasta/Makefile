UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
CFLAGS=-D LINUX -fPIC
endif

ifeq ($(UNAME), Darwin)
CFLAGS=-D OSX
endif

TARGET   = libpasta.so

all: reference_signer unit_tests outso clean

OBJS = base10.o \
	base58.o \
	blake2b-ref.o \
	sha256.o \
	crypto.o \
	pasta_fp.o \
	pasta_fq.o \
	poseidon.o \
	utils.o \
	curve_checks.o



reference_signer: $(OBJS) reference_signer.c
	$(CC) $(CFLAGS) -Wall -Werror $@.c -o $@ $(OBJS) -lm

.PRECIOUS: unit_tests
unit_tests: $(OBJS) *.c *.h
	$(CC) $(CFLAGS) -Wall -Werror $@.c -o $@ $(OBJS) -lm
	@./$@

%.o: %.c %.h
	$(CC) $(CFLAGS) -Wall -Werror $< -c

outso:$(OBJS)
	$(CC) -shared -fPIC -o $(TARGET) $(OBJS)

clean:
	rm -rf *.o *.log reference_signer unit_tests