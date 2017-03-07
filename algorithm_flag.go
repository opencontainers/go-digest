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

type AlgorithmFlag struct {
	Algorithm Algorithm
}

// String implements the flag.Value interface for Algorithms.
// https://golang.org/pkg/flag/#Value
func (flag *AlgorithmFlag) String() string {
	if flag.Algorithm == nil {
		return "unset"
	}
	return flag.Algorithm.String()
}

// Set implements the flag.Value interface for Algorithms.
// https://golang.org/pkg/flag/#Value
func (flag *AlgorithmFlag) Set(value string) error {
	if value == "" {
		flag.Algorithm = Canonical
	} else {
		alg, ok := Algorithms[value]
		if !ok || !alg.Available() {
			return ErrDigestUnsupported
		}

		flag.Algorithm = alg
	}

	return nil
}
