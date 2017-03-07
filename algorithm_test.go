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

package digest_test

import (
	"bytes"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestFroms(t *testing.T) {
	p := make([]byte, 1<<20)
	rand.Read(p)

	for _, alg := range digest.Algorithms {
		h := alg.Hash()
		h.Write(p)
		expected := digest.Digest(fmt.Sprintf("%s:%x", alg, h.Sum(nil)))
		readerDgst, err := alg.FromReader(bytes.NewReader(p))
		if err != nil {
			t.Fatalf("error calculating hash from reader: %v", err)
		}

		dgsts := []digest.Digest{
			alg.FromBytes(p),
			alg.FromString(string(p)),
			readerDgst,
		}

		if alg == digest.Canonical {
			readerDgst, err := digest.FromReader(bytes.NewReader(p))
			if err != nil {
				t.Fatalf("error calculating hash from reader: %v", err)
			}

			dgsts = append(dgsts,
				digest.FromBytes(p),
				digest.FromString(string(p)),
				readerDgst)
		}
		for _, dgst := range dgsts {
			if dgst != expected {
				t.Fatalf("unexpected digest %v != %v", dgst, expected)
			}
		}
	}
}
