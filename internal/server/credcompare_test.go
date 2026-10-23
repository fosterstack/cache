package server

import (
	"strings"
	"testing"
)

// REQ-AUTH-002-AC1 / REQ-AUTH-005-AC4 (release-candidate review, server area): the
// comparison runs on fixed-size digests, so crypto/subtle.ConstantTimeCompare
// never sees inputs of differing length and the credential's byte length is
// not measurable from its early return.
func TestCredentialDigestIsFixedSize(t *testing.T) {
	for _, n := range []int{0, 1, 7, 64, 4096} {
		if got := len(credDigest(strings.Repeat("x", n))); got != 32 {
			t.Errorf("len(credDigest of %d bytes) = %d, want 32", n, got)
		}
	}
}

func TestCredEqualDecidesOnContent(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"s3cret", "s3cret", true},
		{"", "", true},
		{"s3cret", "s3cre", false},
		{"s3cret", "s3cretX", false},
		{"s3cret", "S3cret", false},
		{"", "s3cret", false},
		{strings.Repeat("a", 1000), strings.Repeat("a", 1001), false},
	}
	for _, c := range cases {
		if got := credEqual(c.a, c.b); got != c.want {
			t.Errorf("credEqual(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
