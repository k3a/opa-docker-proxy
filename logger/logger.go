// Package logger provides structured logging setup and request logging for
// opa-docker-proxy.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// textHandler is a custom slog handler that outputs the compact request line.
type textHandler struct {
	level slog.Leveler
	out   io.Writer
}

func (h *textHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	// For "request" messages, output the compact format.
	if r.Message == "request" {
		var (
			clientIP, method, path, userAgent string
			status                            int
			connID                            uint64
		)

		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "client_ip":
				clientIP = a.Value.String()
			case "method":
				method = a.Value.String()
			case "path":
				path = a.Value.String()
			case "status":
				status = int(a.Value.Int64())
			case "user_agent":
				userAgent = a.Value.String()
			case "conn_id":
				connID = a.Value.Uint64()
			}

			return true
		})

		prefix := ""
		if connID > 0 {
			prefix = fmt.Sprintf("[%d] ", connID)
		}

		line := fmt.Sprintf("%s%s %s %s - %d - %q\n", prefix, clientIP, method, path, status, userAgent)
		_, err := h.out.Write([]byte(line))

		return err
	}
	// Fall back to default text formatting for other messages.
	return slog.NewTextHandler(h.out, &slog.HandlerOptions{Level: h.level}).Handle(context.Background(), r)
}

func (h *textHandler) WithAttrs(_attrs []slog.Attr) slog.Handler {
	return h // immutable for simplicity
}

func (h *textHandler) WithGroup(_name string) slog.Handler {
	return h
}

// Setup initialises the global slog logger.
//   - level: one of debug, info, warn, error
//   - format: text or json
//   - w: writer (typically os.Stdout)
func Setup(level, format string, w io.Writer) {
	var lvl slog.Level

	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	var h slog.Handler
	if strings.ToLower(format) == "json" {
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})
	} else {
		h = &textHandler{level: lvl, out: w}
	}

	slog.SetDefault(slog.New(h))
}

// LogRequest logs a proxied request.
// connID is shown as a [N] prefix in the compact log format; pass 0 to omit.
// The actual decision of whether to log is handled by the caller (proxy).
func LogRequest(allowed bool, clientIP, method, path string, status int, userAgent string, connID uint64) {
	level := slog.LevelInfo
	if !allowed {
		level = slog.LevelWarn
	}

	slog.LogAttrs(context.Background(), level, "request",
		slog.String("client_ip", clientIP),
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status", status),
		slog.String("user_agent", userAgent),
		slog.Bool("allowed", allowed),
		slog.Uint64("conn_id", connID),
	)
}
