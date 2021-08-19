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
	"bytes"
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

func TestDigestVerifier(t *testing.T) {
	p := make([]byte, 1<<20)
	rand.Read(p)
	digest := FromBytes(p)

	verifier := digest.Verifier()

	io.Copy(verifier, bytes.NewReader(p))

	if !verifier.Verified() {
		t.Fatalf("bytes not verified")
	}
}

func TestDigestBlakeVector(t *testing.T) {
	// From the BLAKE3 test vectors.
	testvector := Blake3.FromBytes([]byte{0, 1, 2, 3, 4})
	expected := "blake3:b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"
	if string(testvector) != expected {
		t.Fatalf("Expected: %s; Got: %s", expected, testvector)
	}
}

// TestVerifierUnsupportedDigest ensures that unsupported digest validation is
// flowing through verifier creation.
func TestVerifierUnsupportedDigest(t *testing.T) {
	for _, testcase := range []struct {
		Name     string
		Digest   Digest
		Expected interface{} // expected panic target
	}{
		{
			Name:     "Empty",
			Digest:   "",
			Expected: "no ':' separator in digest \"\"",
		},
		{
			Name:     "EmptyAlg",
			Digest:   ":",
			Expected: "empty digest algorithm, validate before calling Algorithm.Hash()",
		},
		{
			Name:     "Unsupported",
			Digest:   Digest("bean:0123456789abcdef"),
			Expected: "bean not available (make sure it is imported)",
		},
		{
			Name:     "Garbage",
			Digest:   Digest("sha256-garbage:pure"),
			Expected: "sha256-garbage not available (make sure it is imported)",
		},
	} {
		t.Run(testcase.Name, func(t *testing.T) {
			expected := testcase.Expected
			defer func() {
				recovered := recover()
				if !reflect.DeepEqual(recovered, expected) {
					t.Fatalf("unexpected recover: %v != %v", recovered, expected)
				}
			}()

			_ = testcase.Digest.Verifier()
		})
	}
}
