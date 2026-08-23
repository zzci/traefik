package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// bcrypt hash of "secret" at MinCost, for config fixtures.
var testHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}()

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := writeFile(path, body); err != nil {
		t.Fatal(err)
	}
	return path
}

var minimalConfig = `
domain: example.com
users:
  - username: alice
    password_hash: "` + testHash + `"
    groups: [admin]
`

func TestConfigDefaults(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "_auth" {
		t.Errorf("cookie_name default: got %q", cfg.CookieName)
	}
	if cfg.AuthHost != "auth.example.com" {
		t.Errorf("auth_host default: got %q", cfg.AuthHost)
	}
	if cfg.Listen != "127.0.0.1:9091" {
		t.Errorf("listen default: got %q", cfg.Listen)
	}
	if time.Duration(cfg.SessionTTL) != 24*time.Hour {
		t.Errorf("session_ttl default: got %v", time.Duration(cfg.SessionTTL))
	}
	if cfg.LoginRateLimit.Attempts != 5 || time.Duration(cfg.LoginRateLimit.Window) != 5*time.Minute {
		t.Errorf("rate limit defaults: got %+v", cfg.LoginRateLimit)
	}
}

func TestConfigExplicitValues(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `
domain: example.com
cookie_name: _zz
auth_host: sso.example.com
session_ttl: 72h
login_rate_limit: { attempts: 3, window: 10m }
users:
  - username: alice
    password_hash: "`+testHash+`"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "_zz" || cfg.AuthHost != "sso.example.com" {
		t.Errorf("got %q %q", cfg.CookieName, cfg.AuthHost)
	}
	if time.Duration(cfg.SessionTTL) != 72*time.Hour {
		t.Errorf("session_ttl: got %v", time.Duration(cfg.SessionTTL))
	}
	if cfg.LoginRateLimit.Attempts != 3 || time.Duration(cfg.LoginRateLimit.Window) != 10*time.Minute {
		t.Errorf("rate limit: got %+v", cfg.LoginRateLimit)
	}
}

func TestConfigErrors(t *testing.T) {
	cases := []struct {
		name, body, wantErr string
	}{
		{"missing domain", `
users:
  - {username: a, password_hash: "` + testHash + `"}`, "domain is required"},
		{"domain with scheme", `
domain: https://example.com
users:
  - {username: a, password_hash: "` + testHash + `"}`, "bare hostname"},
		{"no users", `
domain: example.com`, "at least one user"},
		{"host prefix cookie", `
domain: example.com
cookie_name: __Host-auth
users:
  - {username: a, password_hash: "` + testHash + `"}`, "__Host-"},
		{"bad hash", `
domain: example.com
users:
  - {username: a, password_hash: "plaintext"}`, "bcrypt"},
		{"duplicate user", `
domain: example.com
users:
  - {username: a, password_hash: "` + testHash + `"}
  - {username: a, password_hash: "` + testHash + `"}`, "duplicate"},
		{"bad duration", `
domain: example.com
session_ttl: nonsense
users:
  - {username: a, password_hash: "` + testHash + `"}`, "invalid duration"},
		{"unknown field", `
domain: example.com
nonsense: true
users:
  - {username: a, password_hash: "` + testHash + `"}`, "field nonsense not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestConfigRejectsAuthHostOutsideDomain(t *testing.T) {
	_, err := loadConfig(writeConfig(t, `
domain: example.com
auth_host: login.other.com
users:
  - {username: a, password_hash: "`+testHash+`"}
`))
	if err == nil || !strings.Contains(err.Error(), "auth_host") {
		t.Fatalf("want auth_host validation error, got %v", err)
	}
	// same-domain and subdomain hosts are fine
	if _, err := loadConfig(writeConfig(t, `
domain: example.com
auth_host: example.com
users:
  - {username: a, password_hash: "`+testHash+`"}
`)); err != nil {
		t.Fatalf("apex auth_host should be valid: %v", err)
	}
}

func TestConfigSecret(t *testing.T) {
	if _, err := loadConfig(writeConfig(t, minimalConfig+"secret: tooshort\n")); err == nil ||
		!strings.Contains(err.Error(), "secret") {
		t.Fatal("short secret must error")
	}
	long := strings.Repeat("s", 32)
	cfg, err := loadConfig(writeConfig(t, minimalConfig+"secret: "+long+"\n"))
	if err != nil || cfg.Secret != long {
		t.Fatalf("secret: %q err %v", cfg.Secret, err)
	}
	// env overrides file
	envSecret := strings.Repeat("e", 32)
	t.Setenv("AUTH_SECRET", envSecret)
	cfg, err = loadConfig(writeConfig(t, minimalConfig))
	if err != nil || cfg.Secret != envSecret {
		t.Fatalf("env secret: %q err %v", cfg.Secret, err)
	}
}
