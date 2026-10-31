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
	h := newCredHasher()
	for _, n := range []int{0, 1, 7, 64, 4096} {
		if got := len(h.digest(strings.Repeat("x", n))); got != 32 {
			t.Errorf("len(digest of %d bytes) = %d, want 32", n, got)
		}
	}
}

func TestDigestEqualDecidesOnContent(t *testing.T) {
	h := newCredHasher()
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
		if got := digestEqual(h.digest(c.a), h.digest(c.b)); got != c.want {
			t.Errorf("digestEqual(digest(%q), digest(%q)) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// withAuth digests the configured credentials once, when it is built: the
// digests of two Credentials values are equal exactly when the values are,
// and an unset read-only pair digests like the empty string.
func TestConfiguredDigestsAreComputedFromTheCredentials(t *testing.T) {
	h := newCredHasher()
	a := digestsOf(h, Credentials{Username: "u", Password: "p"})
	b := digestsOf(h, Credentials{Username: "u", Password: "p"})
	c := digestsOf(h, Credentials{Username: "u", Password: "q"})
	if !digestEqual(a.user, b.user) || !digestEqual(a.pass, b.pass) {
		t.Error("equal credentials must have equal digests")
	}
	if !digestEqual(a.user, c.user) || digestEqual(a.pass, c.pass) {
		t.Error("only the changed field's digest may differ")
	}
	if len(digestsOf(h, Credentials{}).user) != 32 {
		t.Error("an unset pair still digests to 32 bytes")
	}
}

// The digest is a keyed HMAC-SHA256 under a key drawn from crypto/rand when
// the hasher is built: it is a comparison aid, not a stored password hash,
// so two hashers (two processes) digest the same secret differently, and a
// secret is never digested the same as the empty string.
func TestCredentialDigestIsKeyedPerHasher(t *testing.T) {
	a, b := newCredHasher(), newCredHasher()
	if digestEqual(a.digest("s3cret"), b.digest("s3cret")) {
		t.Error("two hashers must not agree on the digest of the same secret")
	}
	if !digestEqual(a.digest("s3cret"), a.digest("s3cret")) {
		t.Error("one hasher must digest the same secret the same way")
	}
}

// An empty presented secret never matches a configured one, and an unset
// pair (empty strings) is the digest of the empty string, same hasher.
func TestEmptySecretAgainstUnset(t *testing.T) {
	h := newCredHasher()
	unset := digestsOf(h, Credentials{})
	set := digestsOf(h, Credentials{Username: "u", Password: "p"})
	if !digestEqual(h.digest(""), unset.user) || !digestEqual(h.digest(""), unset.pass) {
		t.Error("an unset pair must digest like the empty string")
	}
	if digestEqual(h.digest(""), set.user) || digestEqual(h.digest(""), set.pass) {
		t.Error("an empty secret must not match a configured one")
	}
}
