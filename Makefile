BINARY  := opa-docker-proxy
PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
CONFDIR := /etc/opa-docker-proxy

.PHONY: all build install clean

all: build

build $(BINARY):
	go build -o $(BINARY) .

install: $(BINARY)
	install -D -m 0755 $(BINARY) $(BINDIR)/$(BINARY)
	mkdir -p $(CONFDIR)/policies
	rsync -a --delete policies/ $(CONFDIR)/policies/

clean:
	rm -f $(BINARY)
