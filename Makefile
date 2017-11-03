default: all

all: bin/certstore bin/certstore.exe

bin:
	mkdir -p bin

bin/certstore: certstore.go certstore_darwin.go main.go bin
	GOOS=darwin go build -o bin/certstore .

bin/certstore.exe: certstore.go certstore_windows.go main.go bin
	GOOS=windows go build -o bin/certstore.exe .
