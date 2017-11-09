package main

func main() {
	idents, err := FindIdentities()
	if err != nil {
		panic(err)
	}

	for _, ident := range idents {
		crt, err := ident.GetCertificate()
		if err != nil {
			panic(err)
		}

		if crt.Subject.CommonName != "Ben Toews" {
			continue
		}

		macIdent := ident.(*macIdentity)

		if err := macIdent.Destroy(); err != nil {
			panic(err)
		}
	}
}
