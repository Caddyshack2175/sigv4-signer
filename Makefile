BINARY := sigv4
GOBIN  ?= $(shell go env GOBIN)

ifeq ($(strip $(GOBIN)),)
GOBIN := $(shell go env GOPATH)/bin
endif

.PHONY: all deps build install test clean

all: deps build test

deps:
	go mod tidy

build: deps
	go build -o $(BINARY) .

install: deps
	mkdir -p "$(GOBIN)"
	go build -o "$(GOBIN)/$(BINARY)" .
	@echo "Installed to $(GOBIN)/$(BINARY)"

test: deps
	go test ./... -v

clean:
	rm -f $(BINARY)
