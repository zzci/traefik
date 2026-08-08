package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// bumpMtime forces a visible mtime change regardless of filesystem
// timestamp granularity.
func bumpMtime(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	next := fi.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, next, next); err != nil {
		t.Fatal(err)
	}
}

func reloadTestServer(t *testing.T, path string) *server {
	t.Helper()
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(cfg, testSecret)
	s.configPath = path
	s.fileStamp = fileStamp(path)
	return s
}

func TestHotReloadPasswordChange(t *testing.T) {
	path := writeConfig(t, minimalConfig) // alice / "secret"
	s := reloadTestServer(t, path)

	if cookie, _ := loginAs(t, s, "alice", "secret", "", "1.1.1.1"); cookie == nil {
		t.Fatal("initial login should work")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte("newpw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(path, strings.Replace(minimalConfig, testHash, string(newHash), 1)); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path)
	s.reloadIfChanged()

	if cookie, _ := loginAs(t, s, "alice", "secret", "", "2.2.2.2"); cookie != nil {
		t.Fatal("old password must stop working after reload")
	}
	if cookie, _ := loginAs(t, s, "alice", "newpw", "", "3.3.3.3"); cookie == nil {
		t.Fatal("new password should work after reload")
	}
}

func TestHotReloadKeepsConfigOnBrokenFile(t *testing.T) {
	path := writeConfig(t, minimalConfig)
	s := reloadTestServer(t, path)

	if err := writeFile(path, "users: [broken"); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path)
	s.reloadIfChanged()

	if cookie, _ := loginAs(t, s, "alice", "secret", "", "4.4.4.4"); cookie == nil {
		t.Fatal("previous config should survive a broken file")
	}
}

func TestHotReloadIgnoresListenAndDataDirChanges(t *testing.T) {
	path := writeConfig(t, minimalConfig)
	s := reloadTestServer(t, path)
	oldListen := s.conf().Listen

	if err := writeFile(path, minimalConfig+"listen: \":1\"\n"); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path)
	s.reloadIfChanged()

	if s.conf().Listen != oldListen {
		t.Fatalf("listen must not hot-reload: got %q", s.conf().Listen)
	}
}

func TestHotReloadNoChangeNoReload(t *testing.T) {
	path := writeConfig(t, minimalConfig)
	s := reloadTestServer(t, path)
	before := s.conf()
	s.reloadIfChanged()
	if s.conf() != before {
		t.Fatal("unchanged file must not swap the config pointer")
	}
}
