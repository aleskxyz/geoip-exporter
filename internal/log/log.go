// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

const SupportedLevels = "debug, info, warn, error"

// syncWriter calls Sync() after each Write to ensure logs appear immediately.
type syncWriter struct{ w io.Writer }

func (s syncWriter) Write(p []byte) (n int, err error) {
	n, err = s.w.Write(p)
	if f, ok := s.w.(*os.File); ok && err == nil {
		f.Sync()
	}
	return n, err
}

// Configure sets the default slog logger level.
func Configure(level string) error {
	l, err := parseLevel(level)
	if err != nil {
		return err
	}
	out := syncWriter{w: os.Stderr}
	slog.SetDefault(slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: l})))
	return nil
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q: must be one of %s", level, SupportedLevels)
	}
}
