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

package digest

import (
	_hex "encoding/hex"
)

// Encoding identifies a hash encoding used by an Algorithm.
type Encoding interface {
	// EncodeToString encodes src to a string.
	EncodeToString(src []byte) string

	// DecodeString decodes s to a byte array.
	DecodeString(s string) (raw []byte, err error)
}

type hex struct{}

var (
	// Hex is a lowercase version of the base 16 encoding defined in RFC
	// 4648.  https://tools.ietf.org/html/rfc4648#section-8
	Hex = hex{}
)

// EncodeToString encodes src to a lowecase base 16 string.
func (h hex) EncodeToString(src []byte) string {
	return _hex.EncodeToString(src)
}

// DecodeString decodes a case-insensitive base 16 string to a byte array.
func (h hex) DecodeString(s string) (raw []byte, err error) {
	return _hex.DecodeString(s)
}
