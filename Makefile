default: all

all: bin/certstore_darwin bin/certstore_windows

bin:
	mkdir -p bin

bin/certstore_darwin: certstore.go certstore_darwin.go certstore_windows.go main.go bin
	GOOS=darwin go build -o bin/certstore_darwin .

bin/certstore_windows: certstore.go certstore_darwin.go certstore_windows.go main.go bin
	GOOS=windows go build -o bin/certstore_windows .
