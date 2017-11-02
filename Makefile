default: bin/keychain

bin:
	mkdir -p bin

bin/keychain: keychain.go keychain_darwin.go keychain_windows.go main.go bin
	go build -o bin/keychain .
