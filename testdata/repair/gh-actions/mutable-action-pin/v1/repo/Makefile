.PHONY: build test clean

build:
	mkdir -p bin
	go build -o bin/chronodex .

test:
	go test ./...

clean:
	rm -rf bin
