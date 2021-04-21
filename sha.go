package digest

import (
	"crypto"
)

const (
	SHA256 Algorithm = "sha256" // sha256 with hex encoding (lower case only)
	SHA384 Algorithm = "sha384" // sha384 with hex encoding (lower case only)
	SHA512 Algorithm = "sha512" // sha512 with hex encoding (lower case only)
)

func init() {
	RegisterAlgorithm(SHA256, crypto.SHA256)
	RegisterAlgorithm(SHA384, crypto.SHA384)
	RegisterAlgorithm(SHA512, crypto.SHA512)
}
