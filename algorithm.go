// Copyright 2019, 2020 OCI Contributors
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
	"fmt"
	"hash"
	"io"
	"regexp"
	"sync"
)

// Algorithm identifies and implementation of a digester by an identifier.
// Note the that this defines both the hash algorithm used and the string
// encoding.
type Algorithm string

// supported digest types
const (
	// Canonical is the primary digest algorithm used with the distribution
	// project. Other digests may be used but this one is the primary storage
	// digest.
	Canonical = SHA256
	// BLAKE3 is the blake3 algorithm with the default 256-bit output size
	// github.com/opencontainers/go-digest/blake3 should be imported to make it available
	BLAKE3 Algorithm = "blake3"
)

var algorithmRegexp = regexp.MustCompile(`^[a-z0-9]+([+._-][a-z0-9]+)*$`)

// CryptoHash is the interface that any hash algorithm must implement
type CryptoHash interface {
	// Available reports whether the given hash function is usable in the current binary.
	Available() bool
	// Size returns the length, in bytes, of a digest resulting from the given hash function.
	Size() int
	// New returns a new hash.Hash calculating the given hash function. If the hash function is not
	// available, it may panic.
	New() hash.Hash
}

var (
	// algorithms maps values to CryptoHash implementations. Other algorithms
	// may be available but they cannot be calculated by the digest package.
	//
	// See: RegisterAlgorithm
	algorithms = map[Algorithm]CryptoHash{}

	// anchoredEncodedRegexps contains anchored regular expressions for hex-encoded digests.
	// Note that /A-F/ disallowed.
	anchoredEncodedRegexps = map[Algorithm]*regexp.Regexp{}

	// algorithmsLock protects algorithms, and anchoredEncodedRegexps
	algorithmsLock sync.RWMutex
)

// RegisterAlgorithm may be called to dynamically register an algorithm. The implementation is a CryptoHash, and
// the regex is meant to match the hash portion of the algorithm. If a duplicate algorithm is already registered,
// the return value is false, otherwise if registration was successful the return value is true.
//
// The algorithm encoding format must be based on hex.
//
// The algorithm name must be conformant to the BNF specification in the OCI image-spec, otherwise the function
// will panic.
func RegisterAlgorithm(algorithm Algorithm, implementation CryptoHash) bool {
	algorithmsLock.Lock()
	defer algorithmsLock.Unlock()

	if !algorithmRegexp.MatchString(string(algorithm)) {
		panic(fmt.Sprintf("Algorithm %s has a name which does not fit within the allowed grammar", algorithm))
	}

	if _, ok := algorithms[algorithm]; ok {
		return false
	}

	algorithms[algorithm] = implementation
	// We can do this since the Digest function below only implements a hex digest. If we open this in the future
	// we need to allow for alternative digest algorithms to be implemented and for the user to pass their own
	// custom regexp.
	anchoredEncodedRegexps[algorithm] = hexDigestRegex(implementation)
	return true
}

// hexDigestRegex can be used to generate a regex for RegisterAlgorithm.
func hexDigestRegex(cryptoHash CryptoHash) *regexp.Regexp {
	hexdigestbytes := cryptoHash.Size() * 2
	return regexp.MustCompile(fmt.Sprintf("^[a-f0-9]{%d}$", hexdigestbytes))
}

// Available returns true if the digest type is available for use. If this
// returns false, Digester and Hash will return nil.
func (a Algorithm) Available() bool {
	algorithmsLock.RLock()
	defer algorithmsLock.RUnlock()

	h, ok := algorithms[a]
	if !ok {
		return false
	}

	// check availability of the hash, as well
	return h.Available()
}

func (a Algorithm) String() string {
	return string(a)
}

// Size returns number of bytes returned by the hash.
func (a Algorithm) Size() int {
	algorithmsLock.RLock()
	defer algorithmsLock.RUnlock()

	h, ok := algorithms[a]
	if !ok {
		return 0
	}
	return h.Size()
}

// Set implemented to allow use of Algorithm as a command line flag.
func (a *Algorithm) Set(value string) error {
	if value == "" {
		*a = Canonical
	} else {
		// just do a type conversion, support is queried with Available.
		*a = Algorithm(value)
	}

	if !a.Available() {
		return ErrDigestUnsupported
	}

	return nil
}

// Digester returns a new digester for the specified algorithm. If the algorithm
// does not have a digester implementation, nil will be returned. This can be
// checked by calling Available before calling Digester.
func (a Algorithm) Digester() Digester {
	return &digester{
		alg:  a,
		hash: a.Hash(),
	}
}

// Hash returns a new hash as used by the algorithm. If not available, the
// method will panic. Check Algorithm.Available() before calling.
func (a Algorithm) Hash() hash.Hash {
	if !a.Available() {
		// Empty algorithm string is invalid
		if a == "" {
			panic("empty digest algorithm, validate before calling Algorithm.Hash()")
		}

		// NOTE(stevvooe): A missing hash is usually a programming error that
		// must be resolved at compile time. We don't import in the digest
		// package to allow users to choose their hash implementation (such as
		// when using stevvooe/resumable or a hardware accelerated package).
		//
		// Applications that may want to resolve the hash at runtime should
		// call Algorithm.Available before call Algorithm.Hash().
		panic(fmt.Sprintf("%v not available (make sure it is imported)", a))
	}

	algorithmsLock.RLock()
	defer algorithmsLock.RUnlock()
	return algorithms[a].New()
}

// Encode encodes the raw bytes of a digest, typically from a hash.Hash, into
// the encoded portion of the digest.
func (a Algorithm) Encode(d []byte) string {
	// TODO(stevvooe): Currently, all algorithms use a hex encoding. When we
	// add support for back registration, we can modify this accordingly.
	//
	// We support dynamic registration now, but we do not allow for the user to
	// specify their own custom format. Hash functions may only use hex encoding.
	return fmt.Sprintf("%x", d)
}

// FromReader returns the digest of the reader using the algorithm.
func (a Algorithm) FromReader(rd io.Reader) (Digest, error) {
	digester := a.Digester()

	if _, err := io.Copy(digester.Hash(), rd); err != nil {
		return "", err
	}

	return digester.Digest(), nil
}

// FromBytes digests the input and returns a Digest.
func (a Algorithm) FromBytes(p []byte) Digest {
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
func (a Algorithm) FromString(s string) Digest {
	return a.FromBytes([]byte(s))
}

// Validate validates the encoded portion string
func (a Algorithm) Validate(encoded string) error {
	algorithmsLock.RLock()
	defer algorithmsLock.RUnlock()

	r, ok := anchoredEncodedRegexps[a]
	if !ok {
		return ErrDigestUnsupported
	}
	// Digests much always be hex-encoded, ensuring that their hex portion will
	// always be size*2
	if a.Size()*2 != len(encoded) {
		return ErrDigestInvalidLength
	}
	if r.MatchString(encoded) {
		return nil
	}
	return ErrDigestInvalidFormat
}
