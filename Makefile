BINARY := trust-flow-analyzer
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/trust-flow-analyzer

test:
	go test ./... -count=1

lint:
	go vet ./...

clean:
	rm -f $(BINARY)
