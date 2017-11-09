default: all

all: bin/certstore

bin:
	mkdir -p bin

bin/certstore: certstore.go certstore_darwin.go main.go bin
	GOOS=darwin go build -o bin/certstore .
