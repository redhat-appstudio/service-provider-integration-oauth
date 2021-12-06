package log

import (
	"fmt"
	"go.uber.org/zap"
	"os"
)

var logger *zap.Logger

var DevMode bool

func ensureLogger() *zap.Logger {
	if logger != nil {
		return logger
	}

	var lgr *zap.Logger
	var err error

	if DevMode {
		lgr, err = zap.NewDevelopment(zap.AddCallerSkip(1))
	} else {
		lgr, err = zap.NewProduction(zap.AddCallerSkip(1))
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to setup the logger: %s", err.Error())
		os.Exit(1)
	}

	logger = lgr

	return logger
}

func Info(msg string, fields ...zap.Field) {
	ensureLogger().Info(msg, fields...)
}

func Debug(msg string, fields ...zap.Field) {
	ensureLogger().Debug(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	ensureLogger().Warn(msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	ensureLogger().Error(msg, fields...)
}
