# base path used to install.
DESTDIR ?= /usr/local

# command name
COMMANDS=embedshim-containerd embedshim-runcext

# binaries
BINARIES=$(addprefix bin/,$(COMMANDS))

# go build command
GO_BUILD_BINARY=go build -o $@ ./$<

GO_GENERATE_CMD=go generate ./...

.PHONY: build binaries

build: binaries

# force to rebuild
REBUILD:

# build a binary from a cmd.
bin/%: cmd/% REBUILD
	make -C bpf
	$(GO_GENERATE_CMD)
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
