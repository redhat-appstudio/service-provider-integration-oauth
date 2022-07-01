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

package controllers

import (
	"fmt"
	"go.uber.org/zap"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	loggerConfig := zap.NewDevelopmentConfig()
	loggerConfig.OutputPaths = []string{"stdout"}
	loggerConfig.ErrorOutputPaths = []string{"stdout"}
	logger, err := loggerConfig.Build()
	if err != nil {
		// there's nothing we can do about the error to print to stderr, but the linter requires us to at least pretend
		_, _ = fmt.Fprintf(os.Stderr, "failed to initialize logging: %s", err.Error())
		os.Exit(1)
	}
	defer func() {
		// linter says we need to handle the error from this call, but this is called after main with no way of us doing
		// anything about the error. So the anon func and this assignment is here purely to make the linter happy.
		_ = logger.Sync()
	}()

	_ = zap.ReplaceGlobals(logger)
	//ctrl.SetLogger(zapr.NewLogger(logger))
	//
	//_ = zap.ReplaceGlobals(logger)
	os.Exit(m.Run())
}
