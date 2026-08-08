package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type duration time.Duration

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = duration(v)
	return nil
}

type RateLimitConfig struct {
	Attempts int      `yaml:"attempts"`
	Window   duration `yaml:"window"`
}

type User struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"`
	Groups       []string `yaml:"groups"`
}

type Config struct {
	Domain         string          `yaml:"domain"`
	CookieName     string          `yaml:"cookie_name"`
	AuthHost       string          `yaml:"auth_host"`
	Listen         string          `yaml:"listen"`
	DataDir        string          `yaml:"data_dir"`
	SessionTTL     duration        `yaml:"session_ttl"`
	LoginRateLimit RateLimitConfig `yaml:"login_rate_limit"`
	Users          []User          `yaml:"users"`
}

// loadConfig builds the effective config: an optional YAML file as the base,
// with AUTH_* environment variables overriding individual fields on top.
// Either source alone is sufficient; neither is required to exist.
func loadConfig(path string) (*Config, error) {
	var cfg Config
	fileUsed := false
	f, err := os.Open(path)
	switch {
	case err == nil:
		func() {
			defer f.Close()
			dec := yaml.NewDecoder(f)
			dec.KnownFields(true)
			err = dec.Decode(&cfg)
		}()
		if errors.Is(err, io.EOF) {
			err = nil // empty file = empty base config
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		fileUsed = true
	case errors.Is(err, os.ErrNotExist):
		// env-only mode
	default:
		return nil, err
	}
	if err := applyEnv(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.applyDefaultsAndValidate(); err != nil {
		if !fileUsed {
			return nil, fmt.Errorf("config (AUTH_* env, no file at %s): %w", path, err)
		}
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaultsAndValidate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if strings.ContainsAny(c.Domain, "/:@ ") {
		return fmt.Errorf("domain must be a bare hostname, got %q", c.Domain)
	}
	if c.CookieName == "" {
		c.CookieName = "_auth"
	}
	if strings.HasPrefix(c.CookieName, "__Host-") || strings.HasPrefix(c.CookieName, "__Secure-") {
		return fmt.Errorf("cookie_name must not use __Host-/__Secure- prefixes (incompatible with Domain attribute)")
	}
	if strings.ContainsAny(c.CookieName, " ;,=") {
		return fmt.Errorf("invalid cookie_name %q", c.CookieName)
	}
	if c.AuthHost == "" {
		c.AuthHost = "auth." + c.Domain
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9091"
	}
	if c.DataDir == "" {
		c.DataDir = "/data/auth"
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = duration(24 * time.Hour)
	}
	if c.LoginRateLimit.Attempts <= 0 {
		c.LoginRateLimit.Attempts = 5
	}
	if c.LoginRateLimit.Window <= 0 {
		c.LoginRateLimit.Window = duration(5 * time.Minute)
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user is required")
	}
	seen := map[string]bool{}
	for i, u := range c.Users {
		if u.Username == "" {
			return fmt.Errorf("users[%d]: username is required", i)
		}
		if seen[u.Username] {
			return fmt.Errorf("duplicate username %q", u.Username)
		}
		seen[u.Username] = true
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return fmt.Errorf("users[%d] (%s): password_hash is not a valid bcrypt hash", i, u.Username)
		}
	}
	return nil
}

func (c *Config) findUser(username string) *User {
	for i := range c.Users {
		if c.Users[i].Username == username {
			return &c.Users[i]
		}
	}
	return nil
}
