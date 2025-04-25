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

package digest_test

import (
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/go-digest/testdigest"
)

func TestParseDigest(t *testing.T) {
	// SHA-384 is not registered by default, but used in this test.
	digest.RegisterAlgorithm(digest.SHA384, crypto.SHA384)

	tests := []testdigest.TestCase{
		{
			Input:     "sha256:e58fcf7418d4390dec8e8fb69d88c06ec07039d651fedd3aa72af9972e7d046b",
			Algorithm: "sha256",
			Encoded:   "e58fcf7418d4390dec8e8fb69d88c06ec07039d651fedd3aa72af9972e7d046b",
		},
		{
			Input:     "sha384:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Algorithm: "sha384",
			Encoded:   "d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
		},
		{
			Input:     "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
			Algorithm: "blake3",
		{
			// empty
			Input: "",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// whitespace only
			Input: "     ",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// empty hex
			Input: "sha256:",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// hex with correct length, but whitespace only
			Input: "sha256:                                                                ",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// empty hex
			Input: ":",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// just hex
			Input: "d41d8cd98f00b204e9800998ecf8427e",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// not hex
			Input: "sha256:d41d8cd98f00b204e9800m98ecf8427e",
			Err:   digest.ErrDigestInvalidLength,
		},
		{
			// too short
			Input: "sha256:abcdef0123456789",
			Err:   digest.ErrDigestInvalidLength,
		},
		{
			// too short (from different Algorithm)
			Input: "sha512:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			Err:   digest.ErrDigestInvalidLength,
		},
		{
			// too short (from different algorithm)
			input: "blake3:abcdef0123456789abcdef0123456789abcdef01234",
			Err:   diest.ErrDigestInvalidLength,
		},
		{
			input: "foo:d41d8cd98f00b204e9800998ecf8427e",
			Err:   digest.ErrDigestUnsupported,
		},
		{
			// repeated separators
			Input: "sha384__foo+bar:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Err:   digest.ErrDigestInvalidFormat,
		},
		{
			// ensure that we parse, but we don't have support for the Algorithm
			Input:     "sha384.foo+bar:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Algorithm: "sha384.foo+bar",
			Encoded:   "d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Err:       digest.ErrDigestUnsupported,
		},
		{
			Input:     "sha384_foo+bar:d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Algorithm: "sha384_foo+bar",
			Encoded:   "d3fc7881460b7e22e3d172954463dddd7866d17597e7248453c48b3e9d26d9596bf9c4a9cf8072c9d5bad76e19af801d",
			Err:       digest.ErrDigestUnsupported,
		},
		{
			Input:     "sha256+b64:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
			Algorithm: "sha256+b64",
			Encoded:   "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
			Err:       digest.ErrDigestUnsupported,
		},
		{
			Input: "sha256:E58FCF7418D4390DEC8E8FB69D88C06EC07039D651FEDD3AA72AF9972E7D046B",
			Err:   digest.ErrDigestInvalidFormat,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.Input, func(t *testing.T) {
			testdigest.RunTestCase(t, tc)
		})
	}
}

func BenchmarkNewDigestFromEncoded(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = digest.NewDigestFromEncoded("sha256", "e58fcf7418d4390dec8e8fb69d88c06ec07039d651fedd3aa72af9972e7d046b")
	}
}

func BenchmarkNewDigestFromBytes(b *testing.B) {
	s := sha256.Sum256([]byte("hello world"))

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = digest.NewDigestFromBytes("sha256", s[:])
	}
}
