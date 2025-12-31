package server

import (
	"context"
	"log/slog"

	"github.com/telepresenceio/dlib/v2/dgroup"
	"github.com/telepresenceio/dlib/v2/dlog"
)

type logger struct {
	context.Context
}

func dlogLevel(level slog.Level) (lvl dlog.LogLevel) {
	switch level {
	case slog.LevelDebug:
		lvl = dlog.LogLevelDebug
	case slog.LevelInfo:
		lvl = dlog.LogLevelInfo
	case slog.LevelWarn:
		lvl = dlog.LogLevelWarn
	default:
		lvl = dlog.LogLevelError
	}
	return lvl
}

func (d *logger) Enabled(ctx context.Context, level slog.Level) bool {
	return dlog.MaxLogLevel(ctx) >= dlogLevel(level)
}

func (d *logger) Handle(ctx context.Context, record slog.Record) error {
	dlog.Log(ctx, dlogLevel(record.Level), record.Message)
	return nil
}

func (d *logger) WithAttrs(attrs []slog.Attr) slog.Handler {
	ctx := d.Context
	for _, attr := range attrs {
		ctx = dlog.WithField(ctx, attr.Key, attr.Value)
	}
	return &logger{ctx}
}

func (d *logger) WithGroup(name string) slog.Handler {
	return &logger{dgroup.WithGoroutineName(d.Context, name)}
}

// Logger creates a github.com/fclairamb/go-log Logger that sends its output
// to a dlog Logger
func Logger(ctx context.Context) *slog.Logger {
	return slog.New(&logger{ctx})
}
