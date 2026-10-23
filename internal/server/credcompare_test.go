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

func TestDigestEqualDecidesOnContent(t *testing.T) {
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
		if got := digestEqual(credDigest(c.a), credDigest(c.b)); got != c.want {
			t.Errorf("digestEqual(credDigest(%q), credDigest(%q)) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// withAuth digests the configured credentials once, when it is built: the
// digests of two Credentials values are equal exactly when the values are,
// and an unset read-only pair digests like the empty string.
func TestConfiguredDigestsAreComputedFromTheCredentials(t *testing.T) {
	a := digestsOf(Credentials{Username: "u", Password: "p"})
	b := digestsOf(Credentials{Username: "u", Password: "p"})
	c := digestsOf(Credentials{Username: "u", Password: "q"})
	if !digestEqual(a.user, b.user) || !digestEqual(a.pass, b.pass) {
		t.Error("equal credentials must have equal digests")
	}
	if !digestEqual(a.user, c.user) || digestEqual(a.pass, c.pass) {
		t.Error("only the changed field's digest may differ")
	}
	if len(digestsOf(Credentials{}).user) != 32 {
		t.Error("an unset pair still digests to 32 bytes")
	}
}
