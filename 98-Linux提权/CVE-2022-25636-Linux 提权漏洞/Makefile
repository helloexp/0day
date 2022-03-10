LDFLAGS = -no-pie -I/usr/include/fuse -lfuse -pthread -lmnl -lnftnl 
CC = gcc

all: exploit

.PHONY: exploit
exploit:
	$(CC) exploit.c fakefuse.c util.c -o exploit $(CFLAGS) $(LDFLAGS)

clean:
	rm -f exploit
