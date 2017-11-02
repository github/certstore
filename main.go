package main

import "os"

func main() {
	ident := findPreferredIdentity("mastahyeti@gmail.com")
	defer ident.Close()

	f, _ := os.Create("key.der")
	f.Write(ident.getPrivateKey().getDER())
	f.Close()
}
