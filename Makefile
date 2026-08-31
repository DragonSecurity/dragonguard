BINARY := bin/dragon
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test lint fmt vet clean install scan selfcheck

all: fmt vet test build

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/dragon
	@echo "built $(BINARY) ($(VERSION))"

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/dragon

test:
	go test ./...

test-verbose:
	go test ./... -v

cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

fmt:
	gofmt -l -w $(shell find . -name '*.go' -not -path './vendor/*')

vet:
	go vet ./...

# Validate the shipped rule pack and policy pack. Both are content, not code,
# so the compiler will not catch a mistake in them.
selfcheck: build
	opengrep scan --config rules --validate
	$(BINARY) policy test policies

# DragonGuard scanning itself.
scan: build
	$(BINARY) scan .

clean:
	rm -rf bin coverage.out
