// Copyright 2021 OCI Contributors
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
	"hash"

	"github.com/zeebo/blake3"
)

const (
	// Blake3 is the blake3 algorithm with the default 256-bit output size
	Blake3 Algorithm = "blake3"

	// BLAKE3 is deprecated. Use the symbol "Blake3" instead.
	BLAKE3 = Blake3
)

func init() {
	RegisterAlgorithm(Blake3, &blake3hash{})
}

type blake3hash struct{}

func (blake3hash) Available() bool {
	return true
}

func (blake3hash) Size() int {
	return blake3.New().Size()
}

func (blake3hash) New() hash.Hash {
	return blake3.New()
}
