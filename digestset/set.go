// Copyright 2020, 2020 OCI Contributors
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

package digestset

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
)

var (
	// ErrDigestNotFound is used when a matching digest
	// could not be found in a set.
	ErrDigestNotFound = errors.New("digest not found")

	// ErrDigestAmbiguous is used when multiple digests
	// are found in a set. None of the matching digests
	// should be considered valid matches.
	ErrDigestAmbiguous = errors.New("ambiguous digest string")
)

// Set holds a unique set of digests that may be referenced by their full or
// shortened string representation.
//
// The uniqueness of a shortened representation depends on the other digests
// in the set. If digests are omitted, collisions in a larger set may not be
// detected. Short representation lookups should therefore always use the
// complete set of digests and an appropriately long short code.
//
// The zero value of Set is ready for use.
type Set struct {
	mutex   sync.RWMutex
	entries []*digestEntry
}

// NewSet creates an empty set of digests
// which may have digests added.
//
// In most cases, new([Set]) (or just declaring a [Set] variable) is
// sufficient to initialize a [Set].
func NewSet() *Set {
	return &Set{}
}

// Lookup looks for a digest matching the given string representation.
// If no digests could be found ErrDigestNotFound will be returned
// with an empty digest value. If multiple matches are found
// ErrDigestAmbiguous will be returned with an empty digest value.
func (dst *Set) Lookup(d string) (digest.Digest, error) {
	dst.mutex.RLock()
	defer dst.mutex.RUnlock()
	if len(dst.entries) == 0 {
		return "", ErrDigestNotFound
	}
	var (
		alg       digest.Algorithm
		hexPrefix string
	)
	if dgst, err := digest.Parse(d); errors.Is(err, digest.ErrDigestInvalidFormat) {
		hexPrefix = d
	} else {
		hexPrefix = dgst.Encoded()
		alg = dgst.Algorithm()
	}
	idx := sort.Search(len(dst.entries), func(i int) bool {
		return dst.entries[i].val >= hexPrefix
	})

	// Entries whose value have hexPrefix as a prefix form a contiguous run starting
	// at idx. Digests of a different algorithm may sort within that run, so a
	// second matching entry is not necessarily adjacent to the first; scan the
	// whole run instead of only inspecting idx and idx+1.
	var match digest.Digest
	for _, entry := range dst.entries[idx:] {
		if !strings.HasPrefix(entry.val, hexPrefix) {
			break
		}
		if alg != "" && entry.alg != alg {
			// Non-matching algorithm.
			continue
		}
		if entry.val == hexPrefix {
			// An exact encoded-value match is unambiguous.
			return entry.digest, nil
		}
		if match != "" {
			return "", ErrDigestAmbiguous
		}
		match = entry.digest
	}
	if match == "" {
		return "", ErrDigestNotFound
	}

	return match, nil
}

// Add adds the given digest to the set. An error will be returned
// if the given digest is invalid. If the digest already exists in the
// set, this operation will be a no-op.
func (dst *Set) Add(d digest.Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	dst.mutex.Lock()
	defer dst.mutex.Unlock()
	entry := &digestEntry{alg: d.Algorithm(), val: d.Encoded(), digest: d}
	idx := sort.Search(len(dst.entries), func(i int) bool {
		if dst.entries[i].val == entry.val {
			return dst.entries[i].alg >= entry.alg
		}
		return dst.entries[i].val >= entry.val
	})
	if idx == len(dst.entries) {
		dst.entries = append(dst.entries, entry)
		return nil
	} else if dst.entries[idx].digest == d {
		return nil
	}

	entries := append(dst.entries, nil)
	copy(entries[idx+1:], entries[idx:len(entries)-1])
	entries[idx] = entry
	dst.entries = entries
	return nil
}

// Remove removes the given digest from the set. An err will be
// returned if the given digest is invalid. If the digest does
// not exist in the set, this operation will be a no-op.
func (dst *Set) Remove(d digest.Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	dst.mutex.Lock()
	defer dst.mutex.Unlock()
	alg, val := d.Algorithm(), d.Encoded()
	idx := sort.Search(len(dst.entries), func(i int) bool {
		if dst.entries[i].val == val {
			return dst.entries[i].alg >= alg
		}
		return dst.entries[i].val >= val
	})
	// Not found if idx is after or value at idx is not digest
	if idx == len(dst.entries) || dst.entries[idx].digest != d {
		return nil
	}

	entries := dst.entries
	copy(entries[idx:], entries[idx+1:])
	entries = entries[:len(entries)-1]
	dst.entries = entries

	return nil
}

// All returns all the digests in the set
func (dst *Set) All() []digest.Digest {
	dst.mutex.RLock()
	defer dst.mutex.RUnlock()
	retValues := make([]digest.Digest, len(dst.entries))
	for i := range dst.entries {
		retValues[i] = dst.entries[i].digest
	}

	return retValues
}

// ShortCodeTable returns a map of Digest to unique short codes. The
// length represents the minimum value, the maximum length may be the
// entire value of digest if uniqueness cannot be achieved without the
// full value. This function will attempt to make short codes as short
// as possible to be unique.
func ShortCodeTable(dst *Set, length int) map[digest.Digest]string {
	dst.mutex.RLock()
	defer dst.mutex.RUnlock()
	shortCodes := make(map[digest.Digest]string, len(dst.entries))
	codeLength := length
	resetIdx := 0
	for i, entry := range dst.entries {
		for {
			if len(entry.val) <= codeLength {
				shortCodes[entry.digest] = entry.digest.String()
				break
			}

			short := entry.val[:codeLength]
			extended := false
			for j := i + 1; j < len(dst.entries); j++ {
				if !strings.HasPrefix(dst.entries[j].val, short) {
					break
				}
				if j > resetIdx {
					resetIdx = j
				}
				extended = true
			}
			if !extended {
				shortCodes[entry.digest] = short
				break
			}
			codeLength++
		}
		if i >= resetIdx {
			codeLength = length
		}
	}
	return shortCodes
}

type digestEntry struct {
	alg    digest.Algorithm
	val    string
	digest digest.Digest
}
