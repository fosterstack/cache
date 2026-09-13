package main

import (
	"strings"
	"testing"
)

// Table-driven config tests (REQ-CFG-001, REQ-CFG-002, REQ-CFG-003).
// t.Setenv scopes each variable to the test and restores it afterward.

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"FSCACHE_ADDR", "FSCACHE_DATA_DIR", "FSCACHE_MAX_BYTES",
		"FSCACHE_MAX_BODY_BYTES", "FSCACHE_USERNAME", "FSCACHE_PASSWORD",
		"FSCACHE_RO_USERNAME", "FSCACHE_RO_PASSWORD"} {
		t.Setenv(k, "")
	}
}

// REQ-CFG-001-AC1: bare environment yields the documented defaults.
func TestDefaultsWithNoEnvironment(t *testing.T) {
	clearEnv(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig with empty env: %v", err)
	}
	if cfg.addr != ":8080" {
		t.Errorf("addr = %q, want :8080", cfg.addr)
	}
	if cfg.dataDir != "./data" {
		t.Errorf("dataDir = %q, want ./data", cfg.dataDir)
	}
	if cfg.maxBytes != 0 {
		t.Errorf("maxBytes = %d, want 0 (unbounded)", cfg.maxBytes)
	}
	if cfg.maxBodyBytes != 1<<30 {
		t.Errorf("maxBodyBytes = %d, want 1 GiB", cfg.maxBodyBytes)
	}
	if cfg.username != "" || cfg.password != "" {
		t.Error("credentials should default to unset")
	}
}

// REQ-CFG-001-AC2: every custom valid value is honored.
func TestCustomValidValuesHonored(t *testing.T) {
	clearEnv(t)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:9999")
	t.Setenv("FSCACHE_DATA_DIR", "/tmp/elsewhere")
	t.Setenv("FSCACHE_MAX_BYTES", "1073741824")
	t.Setenv("FSCACHE_MAX_BODY_BYTES", "1048576")
	t.Setenv("FSCACHE_USERNAME", "u")
	t.Setenv("FSCACHE_PASSWORD", "p")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.addr != "127.0.0.1:9999" || cfg.dataDir != "/tmp/elsewhere" ||
		cfg.maxBytes != 1073741824 || cfg.maxBodyBytes != 1048576 ||
		cfg.username != "u" || cfg.password != "p" {
		t.Errorf("custom values not honored: %+v", cfg)
	}
}

// REQ-CFG-002-AC1: exactly one credential set refuses startup, naming both.
func TestOneCredentialAloneFails(t *testing.T) {
	for _, tc := range []struct{ set, unset string }{
		{"FSCACHE_USERNAME", "FSCACHE_PASSWORD"},
		{"FSCACHE_PASSWORD", "FSCACHE_USERNAME"},
	} {
		t.Run(tc.set+"-only", func(t *testing.T) {
			clearEnv(t)
			t.Setenv(tc.set, "value")
			_, err := loadConfig()
			if err == nil {
				t.Fatal("expected an error with one credential set, got nil")
			}
			if !strings.Contains(err.Error(), "FSCACHE_USERNAME") ||
				!strings.Contains(err.Error(), "FSCACHE_PASSWORD") {
				t.Errorf("error %q does not name both variables", err)
			}
		})
	}
}

// REQ-CFG-003-AC1: invalid numeric configuration fails startup with the
// variable and value named — never a silent default. The trailing-garbage
// case is the audit's exact scenario: a human-units typo ("20GiB") must
// stop the server, not unbound the cache.
func TestInvalidNumericConfigurationFailsStartup(t *testing.T) {
	cases := []struct{ name, value string }{
		{"unparseable", "definitely-not-a-number"},
		{"trailing-garbage", "20GiB"},
		{"negative", "-1"},
		{"overflow", "92233720368547758080"}, // MaxInt64 * 10
		{"float", "1.5"},
		{"hex", "0x10"},
	}
	for _, envVar := range []string{"FSCACHE_MAX_BYTES", "FSCACHE_MAX_BODY_BYTES"} {
		for _, tc := range cases {
			t.Run(envVar+"/"+tc.name, func(t *testing.T) {
				clearEnv(t)
				t.Setenv(envVar, tc.value)
				_, err := loadConfig()
				if err == nil {
					t.Fatalf("%s=%q: expected startup to fail, got nil error (silent fallback)", envVar, tc.value)
				}
				if !strings.Contains(err.Error(), envVar) {
					t.Errorf("error %q does not name %s", err, envVar)
				}
				if !strings.Contains(err.Error(), tc.value) {
					t.Errorf("error %q does not include the offending value %q", err, tc.value)
				}
			})
		}
	}
}

// Zero stays valid: it is the documented "unbounded" for the cache cap and
// "unlimited" for the body cap — fail-closed must not break the documented
// defaults' semantics.
func TestZeroRemainsValid(t *testing.T) {
	clearEnv(t)
	t.Setenv("FSCACHE_MAX_BYTES", "0")
	t.Setenv("FSCACHE_MAX_BODY_BYTES", "0")
	if _, err := loadConfig(); err != nil {
		t.Fatalf("zero must remain valid: %v", err)
	}
}

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

// REQ-AUTH-005-AC3: the read-only pair is fail-closed configuration -
// incomplete, unanchored (no read-write pair), or ambiguous (same
// username) must stop the server before it serves anything.
func TestLoadConfigReadOnlyCredentials(t *testing.T) {
	clearEnv(t)

	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "ro username without ro password",
			env:     map[string]string{"FSCACHE_USERNAME": "ci", "FSCACHE_PASSWORD": "pw", "FSCACHE_RO_USERNAME": "dev"},
			wantErr: "FSCACHE_RO_USERNAME",
		},
		{
			name:    "ro password without ro username",
			env:     map[string]string{"FSCACHE_USERNAME": "ci", "FSCACHE_PASSWORD": "pw", "FSCACHE_RO_PASSWORD": "rpw"},
			wantErr: "FSCACHE_RO_USERNAME",
		},
		{
			name:    "ro pair without read-write pair",
			env:     map[string]string{"FSCACHE_RO_USERNAME": "dev", "FSCACHE_RO_PASSWORD": "rpw"},
			wantErr: "FSCACHE_USERNAME",
		},
		{
			name:    "ro username equals read-write username",
			env:     map[string]string{"FSCACHE_USERNAME": "ci", "FSCACHE_PASSWORD": "pw", "FSCACHE_RO_USERNAME": "ci", "FSCACHE_RO_PASSWORD": "rpw"},
			wantErr: "differ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := loadConfig()
			if err == nil {
				t.Fatalf("loadConfig() = nil error, want error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}

	// A complete, distinct configuration starts and carries both pairs.
	clearEnv(t)
	t.Setenv("FSCACHE_USERNAME", "ci")
	t.Setenv("FSCACHE_PASSWORD", "pw")
	t.Setenv("FSCACHE_RO_USERNAME", "dev")
	t.Setenv("FSCACHE_RO_PASSWORD", "rpw")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() with a complete distinct pair: %v", err)
	}
	if cfg.roUsername != "dev" || cfg.roPassword != "rpw" {
		t.Fatalf("read-only pair not carried: %+v", cfg)
	}
}
