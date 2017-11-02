package main

func main() {
	ident := findPreferredIdentity("mastahyeti@gmail.com")
	defer ident.Close()

	ident.getPrivateKey().get()
}
