# base path used to install.
DESTDIR ?= /usr/local

# command name
COMMANDS=embedshim-containerd

# binaries
BINARIES=$(addprefix bin/,$(COMMANDS))

# go build command
GO_BUILD_BINARY=go build -o $@ ./$<

.PHONY: build binaries

build: binaries

# force to rebuild
REBUILD:

# build a binary from a cmd.
bin/%: cmd/% REBUILD
	$(GO_BUILD_BINARY)

# build binaries
binaries: $(BINARIES)

# install binaries
install:
	@echo "$@ $(DESTDIR)/$(BINARIES)"
	@mkdir -p $(DESTDIR)/bin
	@install $(BINARIES) $(DESTDIR)/bin

clean:
	@rm -rf ./bin
