.PHONY: build test clean

build:
	mkdir -p bin
	go build -o bin/parsefold .

test:
	go test ./...

clean:
	rm -rf bin
