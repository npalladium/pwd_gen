SHELL       ?= /bin/bash -euo pipefail
GO          ?= go
GOOS        ?= $(shell $(GO) env GOOS)
GOARCH      ?= $(shell $(GO) env GOARCH)
CGO_ENABLED ?= $(shell $(GO) env CGO_ENABLED)
BIN         ?= pwd_gen

.PHONY: build test check encrypt

build: main.go
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags="-s -w" -trimpath -o $(BIN) .

test:
	$(GO) test ./...

check: test
	$(GO) vet ./...

encrypt: build
