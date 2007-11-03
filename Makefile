VERSION=0.0.1
DISTNAME=fuseomfs-$(VERSION)
DISTFILES=*.[ch] Makefile README COPYING

SRCS=main.c omfs.c crc.c
OBJS=$(SRCS:.c=.o)

CFLAGS+=-g -Wall -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25 `pkg-config --cflags fuse`

all: omfs

omfs: $(OBJS)
	gcc -o omfs $(OBJS) -lfuse

clean:
	$(RM) omfs *.o

dist: clean
	mkdir $(DISTNAME)
	cp $(DISTFILES) $(DISTNAME)
	tar czvf $(DISTNAME).tar.gz $(DISTNAME)
	$(RM) -r $(DISTNAME)

distcheck: dist
	mkdir build
	cd build && tar xzvf ../$(DISTNAME).tar.gz && \
	cd $(DISTNAME) && $(MAKE)
	$(RM) -r build