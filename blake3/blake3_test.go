// Copyright 2021 OCI Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package blake3

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/go-digest/testdigest"
)

func TestBLAKE3(t *testing.T) {
	testdigest.RunTestCase(t, testdigest.TestCase{
		Input:     "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		Algorithm: "blake3",
		Encoded:   "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
	})
}

func TestBLAKE3Vector(t *testing.T) {
	// From the BLAKE3 test vectors.
	testvector := digest.BLAKE3.FromBytes([]byte{0, 1, 2, 3, 4})
	expected := "blake3:b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"
	if string(testvector) != expected {
		t.Fatalf("Expected: %s; Got: %s", expected, testvector)
	}
}
