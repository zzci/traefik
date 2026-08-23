package main

import (
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func testSession(now time.Time) session {
	return session{
		User:   "alice",
		Groups: []string{"admin", "ops"},
		Iat:    now.Unix(),
		Exp:    now.Add(time.Hour).Unix(),
	}
}

func TestSessionRoundTrip(t *testing.T) {
	now := time.Now()
	token := signSession(testSecret, testSession(now))
	got, err := verifySession(testSecret, token, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.User != "alice" || len(got.Groups) != 2 || got.Groups[0] != "admin" {
		t.Fatalf("unexpected session: %+v", got)
	}
}

func TestSessionExpired(t *testing.T) {
	now := time.Now()
	token := signSession(testSecret, testSession(now))
	if _, err := verifySession(testSecret, token, now.Add(2*time.Hour)); err != errExpired {
		t.Fatalf("want errExpired, got %v", err)
	}
}

func TestSessionIatInFuture(t *testing.T) {
	now := time.Now()
	s := testSession(now.Add(10 * time.Minute))
	token := signSession(testSecret, s)
	if _, err := verifySession(testSecret, token, now); err != errFromFuture {
		t.Fatalf("want errFromFuture, got %v", err)
	}
}

func TestSessionWrongSecret(t *testing.T) {
	now := time.Now()
	token := signSession(testSecret, testSession(now))
	other := []byte("ffffffffffffffffffffffffffffffff")
	if _, err := verifySession(other, token, now); err != errBadSig {
		t.Fatalf("want errBadSig, got %v", err)
	}
}

func TestSessionTampered(t *testing.T) {
	now := time.Now()
	token := signSession(testSecret, testSession(now))
	payload, sig, _ := strings.Cut(token, ".")
	// Swap in a different (validly encoded) payload with the original signature.
	forged := signSession(testSecret, session{User: "root", Iat: now.Unix(), Exp: now.Add(time.Hour).Unix()})
	forgedPayload, _, _ := strings.Cut(forged, ".")
	if _, err := verifySession(testSecret, forgedPayload+"."+sig, now); err != errBadSig {
		t.Fatalf("want errBadSig, got %v", err)
	}
	_ = payload
}

func TestSessionMalformed(t *testing.T) {
	now := time.Now()
	for _, token := range []string{"", "nodot", "a.b", "!!!.###", "e30.e30"} {
		if _, err := verifySession(testSecret, token, now); err == nil {
			t.Fatalf("token %q: want error, got nil", token)
		}
	}
}

func TestLoadSecretGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	s1, err := loadSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s1) < 32 {
		t.Fatalf("secret too short: %d bytes", len(s1))
	}
	s2, err := loadSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(s1) != string(s2) {
		t.Fatal("secret not stable across loads")
	}
}

func TestLoadSecretRejectsShort(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir+"/secret", "short"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecret(dir); err == nil {
		t.Fatal("want error for short secret")
	}
}

func TestResolveSecret(t *testing.T) {
	// configured secret wins, no filesystem touched
	cfg := &Config{Secret: "0123456789abcdef0123456789abcdef", DataDir: "/nonexistent/dir"}
	s, err := resolveSecret(cfg)
	if err != nil || string(s) != cfg.Secret {
		t.Fatalf("configured secret: %q err %v", s, err)
	}
	// no secret configured: falls back to generated+persisted file
	dir := t.TempDir()
	s2, err := resolveSecret(&Config{DataDir: dir})
	if err != nil || len(s2) < 32 {
		t.Fatalf("generated secret: len=%d err %v", len(s2), err)
	}
}
