PREFIX ?= /usr/local
bindir ?= $(PREFIX)/bin
man1dir ?= $(PREFIX)/share/man/man1

CFLAGS ?= -O2 -Wall

all: bgrep

bgrep: bgrep.c

install: bgrep
	install -d $(DESTDIR)$(bindir)
	install -s bgrep $(DESTDIR)$(bindir)/
	install -d $(DESTDIR)$(man1dir)
	install -m 644 bgrep.1 $(DESTDIR)$(man1dir)/

clean:
	rm -f bgrep

.PHONY: all install clean
