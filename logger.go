package main

import (
	"log/slog"
	"os"
	"strings"
)

// logger is the package-level structured logger for all operational events.
// Initialised by initLogger() in main before any command runs.
var logger *slog.Logger

func initLogger() {
	level := &slog.LevelVar{}
	level.Set(parseLogLevel(os.Getenv("LOG_LEVEL")))
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func parseLogLevel(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
