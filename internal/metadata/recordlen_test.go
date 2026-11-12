package metadata

import "testing"

// Metadata record length (rc-1 review): the on-disk value is exactly 16 bytes.
// A value of any other length is corruption and is rejected with the existing
// corrupt-record error, never indexed past its end (a panic inside a bbolt
// View would crash the server on every start).

var badLengths = map[string][]byte{
	"nil":         nil,
	"empty":       {},
	"one byte":    {1},
	"eight bytes": make([]byte, 8),
	"fifteen":     make([]byte, 15),
	"seventeen":   make([]byte, 17),
	"long":        make([]byte, 4096),
}

func TestDecodeRejectsARecordThatIsNot16Bytes(t *testing.T) {
	for name, buf := range badLengths {
		if _, err := decode("k", buf); err == nil {
			t.Errorf("decode of %s: want error, got nil", name)
		}
	}
}

func TestDecodeSizeRejectsARecordThatIsNot16Bytes(t *testing.T) {
	for name, buf := range badLengths {
		if _, err := decodeSize(buf); err == nil {
			t.Errorf("decodeSize of %s: want error, got nil", name)
		}
	}
}

func TestShortRecordIsAnErrorForEveryReader(t *testing.T) {
	for name, buf := range badLengths {
		s := newTestStore(t)
		putRaw(t, s, buf)
		if err := s.Touch("bad"); err == nil {
			t.Errorf("%s: Touch: want error, got nil", name)
		}
		if _, err := s.TotalSize(); err == nil {
			t.Errorf("%s: TotalSize: want error, got nil", name)
		}
		if _, err := s.LeastRecentlyUsed(1); err == nil {
			t.Errorf("%s: LeastRecentlyUsed: want error, got nil", name)
		}
		if _, err := s.All(); err == nil {
			t.Errorf("%s: All: want error, got nil", name)
		}
	}
}
