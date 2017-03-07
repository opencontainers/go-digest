// Copyright 2017 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package digest

import (
	"crypto"
	"fmt"
	"hash"
	"io"
)

type Algorithm interface {
	// Available returns true if the digest type is available for use. If this
	// returns false, Digester and Hash will return nil.
	Available() bool

	// String returns the canonical algorithm identifier for this algorithm.
	String() string

	// Size returns number of bytes in the raw (unencoded) hash.  This
	// gives the size of the hash space. For SHA-256, this will be 32.
	Size() int

	// HashSize returns number of bytes in the encoded hash.  For
	// algorithms which use a base b encoding, HashSize will Size() * 8 /
	// log2(b), possibly rounded up depending on padding.
	HashSize() int

	// Encoding returns the algorithm's Encoding.
	Encoding() Encoding

	// Digester returns a new digester for the algorithm.
	Digester() Digester

	// Hash returns a new hash as used by the algorithm.
	Hash() hash.Hash

	// FromReader returns the digest of the reader using the algorithm.
	FromReader(rd io.Reader) (Digest, error)

	// FromBytes digests the input and returns a Digest.
	FromBytes(p []byte) Digest

	// FromString digests the string input and returns a Digest.
	FromString(s string) Digest
}

// algorithm identifies and implementation of a digester by an identifier.
// Note the that this defines both the hash algorithm used and the string
// encoding.
type algorithm struct {
	name     string
	hash     crypto.Hash
	encoding Encoding
}

// supported digest types
var (
	SHA256 = algorithm{
		name:     "sha256",
		hash:     crypto.SHA256,
		encoding: Hex,
	}

	SHA384 = algorithm{
		name:     "sha384",
		hash:     crypto.SHA384,
		encoding: Hex,
	}

	SHA512 = algorithm{
		name:     "sha512",
		hash:     crypto.SHA512,
		encoding: Hex,
	}

	// Canonical is the primary digest algorithm used with the distribution
	// project. Other digests may be used but this one is the primary storage
	// digest.
	Canonical = SHA256
)

var (
	// Algorithms is a registerable set of Algorithm instances.
	Algorithms = map[string]Algorithm{
		"sha256": SHA256,
		"sha384": SHA384,
		"sha512": SHA512,
	}
)

// Available returns true if the algorithm hash is available for
// use. If this returns false, Digester and Hash will return nil.
func (a algorithm) Available() bool {
	// check availability of the hash, as well
	return a.hash.Available()
}

func (a algorithm) String() string {
	return a.name
}

// Size returns number of bytes in the raw (unencoded) hash.  This
// gives the size of the hash space. For SHA-256, this will be 32.
func (a algorithm) Size() int {
	return a.hash.Size()
}

// HashSize returns number of bytes in the encoded hash.  For
// algorithms which use a base b encoding, HashSize will Size() * 8 /
// log2(b), possibly rounded up depending on padding.
func (a algorithm) HashSize() int {
	if a.encoding == Hex {
		return 2 * a.Size()
	}
	panic(fmt.Sprintf("unrecognized encoding %v", a.encoding))
}

// Encoding returns the algorithm's Encoding.
func (a algorithm) Encoding() Encoding {
	return a.encoding
}

// Digester returns a new digester for the algorithm. If the algorithm
// is unavailable, nil will be returned. This can be checked by
// calling Available before calling Digester.
func (a algorithm) Digester() Digester {
	if !a.Available() {
		return nil
	}

	return &digester{
		name:     a.name,
		hash:     a.Hash(),
		encoding: a.encoding,
	}
}

// Hash returns a new hash as used by the algorithm.  If the algorithm
// is unavailable, nil will be returned.  This can be checked by
// calling Available before calling Hash().
func (a algorithm) Hash() hash.Hash {
	if !a.Available() {
		return nil
	}
	return a.hash.New()
}

// FromReader returns the digest of the reader using the algorithm.
func (a algorithm) FromReader(rd io.Reader) (Digest, error) {
	digester := a.Digester()

	if _, err := io.Copy(digester.Hash(), rd); err != nil {
		return "", err
	}

	return digester.Digest(), nil
}

// FromBytes digests the input and returns a Digest.
func (a algorithm) FromBytes(p []byte) Digest {
	digester := a.Digester()

	if _, err := digester.Hash().Write(p); err != nil {
		// Writes to a Hash should never fail. None of the existing
		// hash implementations in the stdlib or hashes vendored
		// here can return errors from Write. Having a panic in this
		// condition instead of having FromBytes return an error value
		// avoids unnecessary error handling paths in all callers.
		panic("write to hash function returned error: " + err.Error())
	}

	return digester.Digest()
}

// FromString digests the string input and returns a Digest.
func (a algorithm) FromString(s string) Digest {
	return a.FromBytes([]byte(s))
}
