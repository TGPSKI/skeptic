# Standard Makefile for Go project
.PHONY: build test clean

build:
	go build -o bin/app ./cmd/app

test:
	go test ./...

clean:
	rm -rf bin/

deploy:
	kubectl apply -f manifests/
