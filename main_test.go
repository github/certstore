package main

import (
	"bytes"
	"io"
	"os"
)

var rsaPFX, ecPFX []byte

func init() {
	loadRSAPFX()
	loadECPFX()
}

func loadRSAPFX() {
	f, err := os.Open("test_data/rsa.pfx")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		panic(err)
	}

	rsaPFX = buf.Bytes()
}

func loadECPFX() {
	f, err := os.Open("test_data/ec.pfx")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		panic(err)
	}

	ecPFX = buf.Bytes()
}
