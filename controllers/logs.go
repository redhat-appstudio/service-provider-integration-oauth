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
	"net/http"

	"go.uber.org/zap"
)

func LogErrorAndWriteResponse(w http.ResponseWriter, status int, msg string, err error) {
	zap.L().Error(msg, zap.Error(err))
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, err = fmt.Fprintf(w, "%s: %s", msg, err.Error())
	if err != nil {
		zap.L().Error("error recording response error message", zap.Error(err))
	}
}
func LogAndWriteResponse(w http.ResponseWriter, status int, msg string) {
	zap.L().Debug(msg)
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, err := w.Write([]byte(msg))
	if err != nil {
		zap.L().Error("error recording response error message", zap.Error(err))
	}

}

func LogDebugAndWriteResponse(w http.ResponseWriter, status int, msg string, fields ...zap.Field) {
	zap.L().Debug(msg, fields...)
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, err := fmt.Fprint(w, msg)
	if err != nil {
		zap.L().Error("error recording response error message", zap.Error(err))
	}
}
