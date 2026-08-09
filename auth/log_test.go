package main

import (
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "ERROR": slog.LevelError,
	}
	for in, want := range cases {
		got, err := parseLogLevel(in)
		if err != nil || got != want {
			t.Errorf("%q: got %v err %v", in, got, err)
		}
	}
	if _, err := parseLogLevel("verbose"); err == nil {
		t.Fatal("invalid level must error")
	}
}

func TestConfigLogLevel(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, minimalConfig+"log_level: debug\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("got %q", cfg.LogLevel)
	}
	if _, err := loadConfig(writeConfig(t, minimalConfig+"log_level: nope\n")); err == nil {
		t.Fatal("invalid log_level must error")
	}
	t.Setenv("AUTH_LOG_LEVEL", "warn")
	cfg, err = loadConfig(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("env override: got %q", cfg.LogLevel)
	}
}
