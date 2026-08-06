.PHONY: build test

VERSION ?= dev

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/open-tunnelbroker ./cmd/open-tunnelbroker

test:
	go test ./...
