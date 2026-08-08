package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type session struct {
	User   string   `json:"u"`
	Groups []string `json:"g,omitempty"`
	Iat    int64    `json:"iat"`
	Exp    int64    `json:"exp"`
}

var (
	errBadToken   = errors.New("malformed token")
	errBadSig     = errors.New("bad signature")
	errExpired    = errors.New("session expired")
	errFromFuture = errors.New("session issued in the future")
)

const maxClockSkew = time.Minute

var b64 = base64.RawURLEncoding

func signSession(secret []byte, s session) string {
	payload, err := json.Marshal(s)
	if err != nil {
		// session contains only plain strings/ints; Marshal cannot fail
		panic(err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(mac.Sum(nil))
}

func verifySession(secret []byte, token string, now time.Time) (session, error) {
	var s session
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return s, errBadToken
	}
	payload, err := b64.DecodeString(payloadB64)
	if err != nil {
		return s, errBadToken
	}
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return s, errBadToken
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return s, errBadSig
	}
	if err := json.Unmarshal(payload, &s); err != nil {
		return s, errBadToken
	}
	if s.User == "" {
		return session{}, errBadToken
	}
	if now.Unix() >= s.Exp {
		return session{}, errExpired
	}
	if s.Iat > now.Add(maxClockSkew).Unix() {
		return session{}, errFromFuture
	}
	return s, nil
}

// loadSecret returns the HMAC secret from <dataDir>/secret, generating and
// persisting a random one on first boot.
func loadSecret(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, "secret")
	if b, err := os.ReadFile(path); err == nil {
		secret := []byte(strings.TrimSpace(string(b)))
		if len(secret) < 32 {
			return nil, fmt.Errorf("%s: secret too short (need >= 32 bytes)", path)
		}
		return secret, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	secret := []byte(base64.RawStdEncoding.EncodeToString(raw))
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, err
	}
	return secret, nil
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64.EncodeToString(b)
}
