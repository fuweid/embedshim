# base path used to install.
DESTDIR ?= /usr/local

# Used to populate variables in version package.
PKG=github.com/containerd/containerd

VERSION ?= $(shell git describe --match 'v[0-9]*' --dirty='.m' --always)
REVISION=$(shell git rev-parse HEAD)$(shell if ! git diff --no-ext-diff --quiet --exit-code; then echo .m; fi)

CONTAINERD_LDFLAGS=-ldflags '-X $(PKG)/version.Version=$(VERSION) -X $(PKG)/version.Revision=$(REVISION)'

# go build command
GO_BUILD_BINARY=go build -o $@ ./$<

GO_GENERATE_CMD=go generate ./...

COMMANDS=embedshim-containerd embedshim-runcext

# binaries
BINARIES=$(addprefix bin/,$(COMMANDS))

.PHONY: build binaries

binaries: $(BINARIES)

# force to rebuild
REBUILD:

bin/embedshim-containerd: cmd/embedshim-containerd REBUILD
	@echo "$@"
	@make -C bpf
	$(GO_GENERATE_CMD)
	@go build -o $@ ${CONTAINERD_LDFLAGS} ./cmd/embedshim-containerd

bin/embedshim-runcext: cmd/embedshim-runcext REBUILD
	@echo "$@"
	@go build -o $@ ./cmd/embedshim-runcext

# install binaries
install:
	@echo "$@ $(DESTDIR)/$(BINARIES)"
	@mkdir -p $(DESTDIR)/bin
	@install $(BINARIES) $(DESTDIR)/bin

clean:
	@rm -rf ./bin
	@rm -rf ./bpf/.output
