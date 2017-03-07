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
	_ "crypto/sha256"
	_ "crypto/sha512"
	"flag"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestFlagInterface(t *testing.T) {
	var (
		algFlag digest.AlgorithmFlag
		flagSet flag.FlagSet
	)

	flagSet.Var(&algFlag, "algorithm", "set the digest algorithm")
	for _, testcase := range []struct {
		Name     string
		Args     []string
		Err      error
		Expected digest.Algorithm
	}{
		{
			Name: "Invalid",
			Args: []string{"-algorithm", "bean"},
			Err:  digest.ErrDigestUnsupported,
		},
		{
			Name:     "Default",
			Args:     []string{"unrelated"},
			Expected: digest.SHA256,
		},
		{
			Name:     "Other",
			Args:     []string{"-algorithm", "sha512"},
			Expected: digest.SHA512,
		},
	} {
		t.Run(testcase.Name, func(t *testing.T) {
			algFlag = digest.AlgorithmFlag{
				Algorithm: digest.Canonical,
			}
			if err := flagSet.Parse(testcase.Args); err != testcase.Err {
				if testcase.Err == nil {
					t.Fatal("unexpected error", err)
				}

				// check that flag package returns correct error
				if !strings.Contains(err.Error(), testcase.Err.Error()) {
					t.Fatalf("unexpected error: %v != %v", err, testcase.Err)
				}
				return
			}

			if algFlag.Algorithm != testcase.Expected {
				t.Fatalf("unexpected algorithm: %v != %v", algFlag.Algorithm, testcase.Expected)
			}
		})
	}
}
