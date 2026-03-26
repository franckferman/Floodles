CC      = gcc
CFLAGS  = -O3 -march=native -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -lpthread

all: sender libsender.so

# Standalone binary (for testing without Python)
sender: sender.c
	$(CC) $(CFLAGS) -DBUILD_STANDALONE -o sender sender.c $(LDFLAGS)

# Shared library (for Python ctypes integration)
libsender.so: sender.c
	$(CC) $(CFLAGS) -shared -fPIC -o libsender.so sender.c $(LDFLAGS)

clean:
	rm -f sender libsender.so

.PHONY: all clean
