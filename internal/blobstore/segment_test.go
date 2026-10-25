package blobstore

import (
	"regexp"
	"strings"
	"testing"
)

// segmentOracle is the grammar of a safe path segment as it was first written
// (a regular expression). TestSegmentOK holds the hand-written check to it.
var segmentOracle = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)

func TestSegmentOK(t *testing.T) {
	cases := []string{"", "a", "..", ".", "a-b_c.D9", "+tmp", "a b", "a/b", "a\n", "\na", "a\x00", "é", "日本", "aéb"}
	for b := 0; b < 256; b++ {
		cases = append(cases, string([]byte{byte(b)}), "a"+string([]byte{byte(b)}), string([]byte{byte(b)})+"a")
	}
	for _, n := range []int{254, 255, 256, 257} {
		cases = append(cases, strings.Repeat("a", n), strings.Repeat("a", n-1)+"\n")
	}
	for _, c := range cases {
		if got, want := segmentOK(c), segmentOracle.MatchString(c); got != want {
			t.Errorf("segmentOK(%q) = %v, the grammar says %v", c, got, want)
		}
	}
}
