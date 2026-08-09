package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// applyEnv overrides individual config fields from AUTH_* environment
// variables. Unset/empty variables leave the field untouched, so env vars
// can be used alone or layered over a config file:
//
//	AUTH_DOMAIN       example.com
//	AUTH_USERS        user:secret[:g1|g2],user2:...   (replaces the user list)
//	AUTH_COOKIE_NAME  _auth
//	AUTH_HOST         auth.example.com
//	AUTH_SESSION_TTL  24h
//	AUTH_RATE_LIMIT   5/5m
//
// A secret starting with "$2" is taken as a bcrypt hash, anything else as a
// plaintext password and hashed at startup. Plaintext passwords must not
// contain ":" or ",".
func applyEnv(cfg *Config) error {
	if v := os.Getenv("AUTH_DOMAIN"); v != "" {
		cfg.Domain = v
	}
	if v := os.Getenv("AUTH_COOKIE_NAME"); v != "" {
		cfg.CookieName = v
	}
	if v := os.Getenv("AUTH_HOST"); v != "" {
		cfg.AuthHost = v
	}
	if v := os.Getenv("AUTH_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("AUTH_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("AUTH_SESSION_TTL: %w", err)
		}
		cfg.SessionTTL = duration(d)
	}
	if v := os.Getenv("AUTH_RATE_LIMIT"); v != "" {
		attempts, window, ok := strings.Cut(v, "/")
		n, atoiErr := strconv.Atoi(attempts)
		if !ok || atoiErr != nil || n <= 0 {
			return fmt.Errorf("AUTH_RATE_LIMIT must be <attempts>/<window>, e.g. 5/5m")
		}
		d, err := time.ParseDuration(window)
		if err != nil {
			return fmt.Errorf("AUTH_RATE_LIMIT window: %w", err)
		}
		cfg.LoginRateLimit = RateLimitConfig{Attempts: n, Window: duration(d)}
	}
	if v := os.Getenv("AUTH_USERS"); v != "" {
		var users []User
		for i, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			u, err := parseUserEntry(entry)
			if err != nil {
				// never echo the entry itself: it may contain a plaintext secret
				return fmt.Errorf("AUTH_USERS entry %d: %w", i+1, err)
			}
			users = append(users, u)
		}
		cfg.Users = users
	}
	return nil
}

func parseUserEntry(entry string) (User, error) {
	parts := strings.SplitN(entry, ":", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return User{}, fmt.Errorf("want user:secret[:group|group]")
	}
	u := User{Username: parts[0]}
	if secret := parts[1]; strings.HasPrefix(secret, "$2") {
		u.PasswordHash = secret
	} else {
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcryptCost)
		if err != nil {
			return User{}, fmt.Errorf("hash password for %q: %w", u.Username, err)
		}
		u.PasswordHash = string(hash)
	}
	if len(parts) == 3 {
		for _, g := range strings.Split(parts[2], "|") {
			if g = strings.TrimSpace(g); g != "" {
				u.Groups = append(u.Groups, g)
			}
		}
	}
	return u, nil
}
