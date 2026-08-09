package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// logLevel is shared with the slog default handler so config hot-reloads
// can change verbosity without restart.
var logLevel = new(slog.LevelVar)

func initLogger() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("invalid log_level %q (want debug|info|warn|error)", s)
}

func applyLogLevel(s string) {
	if lvl, err := parseLogLevel(s); err == nil {
		logLevel.Set(lvl)
	}
}
