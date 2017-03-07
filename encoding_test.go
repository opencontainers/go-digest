// Copyright 2017 go-digest contributors
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
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestHexEncode(t *testing.T) {
	string := digest.Hex.EncodeToString([]byte{0x66, 0x6f, 0x6f})
	if string != "666f6f" {
		t.Fatalf("error encoding 66 6f 6f to hex: %v", string)
	}
}

func TestHexDecode(t *testing.T) {
	raw, err := digest.Hex.DecodeString("666f6f")
	if err != nil {
		t.Fatalf("error decoding 666f6f from hex: %v", err)
	}
	if !bytes.Equal(raw, []byte{0x66, 0x6f, 0x6f}) {
		t.Fatalf("error decoding 666f6f from hex: %v", raw)
	}
}

func TestUppercaseHexDecode(t *testing.T) {
	raw, err := digest.Hex.DecodeString("666F6F")
	if err != nil {
		t.Fatalf("error decoding 666F6F from hex: %v", err)
	}
	if !bytes.Equal(raw, []byte{0x66, 0x6f, 0x6f}) {
		t.Fatalf("error decoding 666F6F from hex: %v", raw)
	}
}
