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

import "hash"

// Digester calculates the digest of written data. Writes should go directly
// to the return value of Hash, while calling Digest will return the current
// value of the digest.
type Digester interface {
	// Hash provides direct access to the underlying Hash instance.
	Hash() hash.Hash

	// Digest returns the digest of the currently-hashed content.
	Digest() Digest
}

// digester provides a simple digester definition that embeds a hasher.
type digester struct {
	name     string
	hash     hash.Hash
	encoding Encoding
}

func NewDigester(alg Algorithm, hash hash.Hash) Digester {
	return &digester{
		name:     alg.String(),
		hash:     hash,
		encoding: alg.Encoding(),
	}
}

// Hash provides direct access to the underlying Hash instance.
func (d *digester) Hash() hash.Hash {
	return d.hash
}

// hashString returns the current encoded hash.
func (d *digester) hashString() string {
	return d.encoding.EncodeToString(d.hash.Sum(nil))
}

// Digest returns the digest of the currently-hashed content.
func (d *digester) Digest() Digest {
	return NewDigestFromHash(d.name, d.hashString())
}
