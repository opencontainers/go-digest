package digest

import "testing"

func FuzzParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		Parse(string(data))
		return
	})
}
