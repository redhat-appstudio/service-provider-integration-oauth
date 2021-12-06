// Copyright (c) 2021 Red Hat, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"fmt"
	"os"

	"go.uber.org/zap"
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
