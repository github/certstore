default: bin/certstore

bin:
	mkdir -p bin

bin/certstore: certstore.go certstore_darwin.go certstore_windows.go main.go bin
	go build -o bin/certstore .
