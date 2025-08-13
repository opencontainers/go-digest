.PHONY: all build test

all: build test

build:
	go build -v ./...

test:
	go test -v -cover -race ./...
