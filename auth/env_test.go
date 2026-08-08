package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func setAuthEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for _, k := range []string{"AUTH_DOMAIN", "AUTH_USERS", "AUTH_COOKIE_NAME",
		"AUTH_HOST", "AUTH_SESSION_TTL", "AUTH_RATE_LIMIT"} {
		t.Setenv(k, vars[k])
	}
}

// missingPath returns a config path that does not exist (env-only mode).
func missingPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "none.yml")
}

func TestEnvOnlyConfigFull(t *testing.T) {
	setAuthEnv(t, map[string]string{
		"AUTH_DOMAIN":      "example.com",
		"AUTH_USERS":       "admin:" + testHash + ":admin|ops, bob:plainpw",
		"AUTH_COOKIE_NAME": "_zz",
		"AUTH_HOST":        "sso.example.com",
		"AUTH_SESSION_TTL": "72h",
		"AUTH_RATE_LIMIT":  "3/10m",
	})
	cfg, err := loadConfig(missingPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "example.com" || cfg.CookieName != "_zz" || cfg.AuthHost != "sso.example.com" {
		t.Fatalf("basic fields: %+v", cfg)
	}
	if time.Duration(cfg.SessionTTL) != 72*time.Hour {
		t.Errorf("ttl: %v", time.Duration(cfg.SessionTTL))
	}
	if cfg.LoginRateLimit.Attempts != 3 || time.Duration(cfg.LoginRateLimit.Window) != 10*time.Minute {
		t.Errorf("rate limit: %+v", cfg.LoginRateLimit)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("users: %+v", cfg.Users)
	}
	admin := cfg.Users[0]
	if admin.Username != "admin" || admin.PasswordHash != testHash ||
		strings.Join(admin.Groups, ",") != "admin,ops" {
		t.Errorf("admin: %+v", admin)
	}
	// bob's plaintext password must be bcrypt-hashed at load time
	bob := cfg.Users[1]
	if bob.Username != "bob" || bob.PasswordHash == "plainpw" {
		t.Fatalf("bob: %+v", bob)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(bob.PasswordHash), []byte("plainpw")); err != nil {
		t.Error("bob's hashed password does not verify")
	}
}

func TestEnvOnlyConfigDefaults(t *testing.T) {
	setAuthEnv(t, map[string]string{
		"AUTH_DOMAIN": "example.com",
		"AUTH_USERS":  "admin:pw",
	})
	cfg, err := loadConfig(missingPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "_auth" || cfg.AuthHost != "auth.example.com" {
		t.Errorf("defaults: %+v", cfg)
	}
	if cfg.LoginRateLimit.Attempts != 5 {
		t.Errorf("rate limit default: %+v", cfg.LoginRateLimit)
	}
}

func TestEnvOverridesConfigFile(t *testing.T) {
	path := writeConfig(t, `
domain: file.com
cookie_name: _file
session_ttl: 12h
users:
  - username: fileuser
    password_hash: "`+testHash+`"
    groups: [viewer]
`)
	setAuthEnv(t, map[string]string{
		"AUTH_DOMAIN":      "env.com",
		"AUTH_COOKIE_NAME": "_env",
		"AUTH_USERS":       "envuser:" + testHash + ":admin",
	})
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "env.com" || cfg.CookieName != "_env" {
		t.Errorf("env should override file: %+v", cfg)
	}
	// fields not set via env keep the file values
	if time.Duration(cfg.SessionTTL) != 12*time.Hour {
		t.Errorf("file session_ttl should survive: %v", time.Duration(cfg.SessionTTL))
	}
	// AUTH_USERS replaces the whole user list
	if len(cfg.Users) != 1 || cfg.Users[0].Username != "envuser" {
		t.Errorf("users: %+v", cfg.Users)
	}
	// auth_host default derives from the effective (env) domain
	if cfg.AuthHost != "auth.env.com" {
		t.Errorf("auth_host: %q", cfg.AuthHost)
	}
}

func TestEnvPartialOverlayOnFile(t *testing.T) {
	path := writeConfig(t, minimalConfig) // domain example.com, user alice
	setAuthEnv(t, map[string]string{"AUTH_COOKIE_NAME": "_only"})
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieName != "_only" || cfg.Domain != "example.com" || cfg.Users[0].Username != "alice" {
		t.Errorf("overlay: %+v", cfg)
	}
}

func TestEmptyConfigFileWithEnv(t *testing.T) {
	path := writeConfig(t, "")
	setAuthEnv(t, map[string]string{
		"AUTH_DOMAIN": "example.com",
		"AUTH_USERS":  "admin:pw",
	})
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("empty file should be a valid base: %v", err)
	}
}

func TestEnvConfigErrors(t *testing.T) {
	cases := []struct {
		name    string
		vars    map[string]string
		wantErr string
	}{
		{"missing domain", map[string]string{"AUTH_USERS": "a:b"}, "domain is required"},
		{"no users", map[string]string{"AUTH_DOMAIN": "example.com"}, "at least one user"},
		{"bad entry", map[string]string{
			"AUTH_DOMAIN": "example.com", "AUTH_USERS": "justname"}, "entry 1"},
		{"empty secret", map[string]string{
			"AUTH_DOMAIN": "example.com", "AUTH_USERS": "a:"}, "entry 1"},
		{"bad rate limit", map[string]string{
			"AUTH_DOMAIN": "example.com", "AUTH_USERS": "a:b", "AUTH_RATE_LIMIT": "lots"}, "AUTH_RATE_LIMIT"},
		{"bad ttl", map[string]string{
			"AUTH_DOMAIN": "example.com", "AUTH_USERS": "a:b", "AUTH_SESSION_TTL": "soon"}, "AUTH_SESSION_TTL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAuthEnv(t, tc.vars)
			_, err := loadConfig(missingPath(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestEnvConfigErrorDoesNotLeakSecret(t *testing.T) {
	setAuthEnv(t, map[string]string{
		"AUTH_DOMAIN": "example.com",
		"AUTH_USERS":  ":supersecretpw",
	})
	_, err := loadConfig(missingPath(t))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "supersecretpw") {
		t.Fatalf("error leaks secret: %v", err)
	}
}
