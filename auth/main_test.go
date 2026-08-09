package main

import "testing"

func TestResolveConfigPath(t *testing.T) {
	t.Setenv("AUTH_CONFIG", "")
	if got := resolveConfigPath(""); got != defaultConfigPath {
		t.Fatalf("default: got %q", got)
	}
	t.Setenv("AUTH_CONFIG", "/etc/custom.yml")
	if got := resolveConfigPath(""); got != "/etc/custom.yml" {
		t.Fatalf("env: got %q", got)
	}
	if got := resolveConfigPath("/flag.yml"); got != "/flag.yml" {
		t.Fatalf("flag must win over env: got %q", got)
	}
}
