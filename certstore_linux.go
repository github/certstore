package certstore

import (
	"errors"
	"log"
)

// This will hopefully give a compiler error that will hint at the fact that
// this package isn't designed to work on Linux.
func init() {
	log.Fatal("certstore only works on macOS and Windows")
}

// Implement this function, just to silence other compiler errors.
func openStore() (Store, error) {
	return nil, errors.New("certstore only works on macOS and Windows")
}
