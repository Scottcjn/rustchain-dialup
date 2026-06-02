# vintage_client — RustChain dial-up vintage miner client (bounty D6)
#
#   make                     # OpenSSL Ed25519 backend (modern + 486-Linux dev box)
#   make CRYPTO=monocypher   # portable vintage target — drop monocypher.c/.h here first
#   make clean
#
# For genuine vintage targets, cross-compile with the period toolchain and prefer
# CRYPTO=monocypher (OpenSSL is far too heavy for a 68k/SH-4).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu99
CRYPTO  ?= openssl

OBJS = vintage_client.o rcc_crypto.o

ifeq ($(CRYPTO),monocypher)
  CFLAGS += -DRCC_MONOCYPHER
  OBJS   += monocypher.o
  LIBS    =
else
  LIBS    = -lcrypto
endif

vintage_client: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f vintage_client $(OBJS)

.PHONY: clean
