package main

import "testing"

// REQ-STORE-005-AC3, the marker half: present after write, absent after
// clear, detection distinguishes the two, and clearing an absent marker
// is not an error (idempotent clean shutdown).
func TestUncleanShutdownMarkerLifecycle(t *testing.T) {
	dir := t.TempDir()
	m := uncleanMarkerPath(dir)

	present, err := markerPresent(m)
	if err != nil || present {
		t.Fatalf("fresh dir: present=%v err=%v, want false nil", present, err)
	}
	if err := writeMarker(m); err != nil {
		t.Fatalf("writeMarker: %v", err)
	}
	if present, _ = markerPresent(m); !present {
		t.Fatal("marker not detected after write")
	}
	if err := clearMarker(m); err != nil {
		t.Fatalf("clearMarker: %v", err)
	}
	if present, _ = markerPresent(m); present {
		t.Fatal("marker still present after clear")
	}
	if err := clearMarker(m); err != nil {
		t.Fatalf("clearing an absent marker must be a no-op, got %v", err)
	}
}
