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
	"strings"
)

// Digest allows simple protection of algorithm-prefixed
// hashes. Strings of type Digest have some guarantee of being in the
// correct format and it provides quick access to the components of a
// digest string.
//
// The following is an example of the contents of Digest types:
//
// 	sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc
//
// This allows to abstract the digest behind this type and work only in those
// terms.
type Digest string

// NewDigest is deprecated.  Use NewDigester(...).Digest() instead.
func NewDigest(alg Algorithm, h hash.Hash) Digest {
	return NewDigester(alg, h).Digest()
}

// NewDigestFromBytes returns a new digest from the byte contents of p.
// Typically, this can come from hash.Hash.Sum(...) or xxx.SumXXX(...)
// functions. This is also useful for rebuilding digests from binary
// serializations.
func NewDigestFromBytes(alg Algorithm, p []byte) Digest {
	return NewDigestFromHash(alg.String(), alg.Encoding().EncodeToString(p))
}

// NewDigestFromHash returns a Digest from the algorithm and hash.
func NewDigestFromHash(alg, hash string) Digest {
	return Digest(fmt.Sprintf("%s:%s", alg, hash))
}

// NewDigestFromHex is deprecated. Use NewDigestFromHash instead.
func NewDigestFromHex(alg, hex string) Digest {
	return NewDigestFromHash(alg, hex)
}

// DigestRegexp matches valid digest types.
var DigestRegexp = regexp.MustCompile(`[a-zA-Z0-9-_+.]+:[a-fA-F0-9]+`)

// DigestRegexpAnchored matches valid digest types, anchored to the start and end of the match.
var DigestRegexpAnchored = regexp.MustCompile(`^` + DigestRegexp.String() + `$`)

var (
	// ErrDigestInvalidFormat returned when digest format invalid.
	ErrDigestInvalidFormat = fmt.Errorf("invalid checksum digest format")

	// ErrDigestInvalidLength returned when digest has invalid length.
	ErrDigestInvalidLength = fmt.Errorf("invalid checksum digest length")

	// ErrDigestUnsupported returned when the digest algorithm is unsupported.
	ErrDigestUnsupported = fmt.Errorf("unsupported digest algorithm")
)

// Parse parses s and returns the validated digest object. An error will
// be returned if the format is invalid.
func Parse(s string) (Digest, error) {
	d := Digest(s)
	return d, d.Validate()
}

// FromReader consumes the content of rd until io.EOF, returning canonical digest.
func FromReader(rd io.Reader) (Digest, error) {
	return Canonical.FromReader(rd)
}

// FromBytes digests the input and returns a Digest.
func FromBytes(p []byte) Digest {
	return Canonical.FromBytes(p)
}

// FromString digests the input and returns a Digest.
func FromString(s string) Digest {
	return Canonical.FromString(s)
}

// Validate checks that the contents of d is a valid digest, returning an
// error if not.
func (d Digest) Validate() error {
	s := string(d)

	i := strings.Index(s, ":")

	// validate i then run through regexp
	if i < 0 || i+1 == len(s) || !DigestRegexpAnchored.MatchString(s) {
		return ErrDigestInvalidFormat
	}

	algorithm, ok := Algorithms[s[:i]]
	if !ok || !algorithm.Available() {
		return ErrDigestUnsupported
	}

	if algorithm.HashSize() != len(s[i+1:]) {
		return ErrDigestInvalidLength
	}

	return nil
}

// Algorithm returns the algorithm portion of the digest. This will panic if
// the underlying digest is not in a valid format.
func (d Digest) Algorithm() Algorithm {
	identifier := string(d)[:d.sepIndex()]
	if identifier == "" {
		panic(fmt.Sprintf("empty digest algorithm for %v", d))
	}
	alg, ok := Algorithms[identifier]
	if !ok {
		panic(fmt.Sprintf("unrecognized algorithm %v", identifier))
	}
	if !alg.Available() {
		panic(fmt.Sprintf("unavailable algorithm %v", identifier))
	}
	return alg
}

// Verifier returns a writer object that can be used to verify a stream of
// content against the digest. If the digest is invalid, the method will panic.
func (d Digest) Verifier() Verifier {
	return hashVerifier{
		digest:   d,
		digester: d.Algorithm().Digester(),
	}
}

// Hash returns the hash portion of the digest. This will panic if the
// underlying digest is not in a valid format.
func (d Digest) Hash() string {
	return string(d[d.sepIndex()+1:])
}

// Hex is is deprecated. Use Hash instead.
func (d Digest) Hex() string {
	return d.Hash()
}

func (d Digest) String() string {
	return string(d)
}

func (d Digest) sepIndex() int {
	i := strings.Index(string(d), ":")

	if i < 0 {
		panic(fmt.Sprintf("no ':' separator in digest %q", d))
	}

	return i
}
