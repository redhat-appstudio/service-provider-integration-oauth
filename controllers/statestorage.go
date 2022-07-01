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
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"go.uber.org/zap"
)

type StateStorage struct {
	sessionManager *scs.SessionManager
}

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyz1234567890"
)

func (storage StateStorage) VeilRealState(req *http.Request) (string, error) {
	state := req.URL.Query().Get("state")
	if state == "" {
		zap.L().Error("Request has no state parameter")
		return "", errors.New("request has no `state` parameter")
	}
	newState, err := randStringBytes(32)
	if err != nil {

		return "", err
	}
	zap.L().Debug("State veiled", zap.String("state", state), zap.String("veil", newState))
	storage.sessionManager.Put(req.Context(), newState, state)
	return newState, nil
}

func (storage StateStorage) UnveilState(req *http.Request) (string, error) {
	state := req.URL.Query().Get("state")
	if state == "" {
		zap.L().Error("Request has no state parameter")
		return "", errors.New("request has no `state` parameter")
	}
	unveiledState := storage.sessionManager.GetString(req.Context(), state)
	zap.L().Debug("State unveiled", zap.String("veil", state), zap.String("unveiledState", unveiledState))
	return unveiledState, nil
}

func randStringBytes(n int) (string, error) {
	b := make([]byte, n)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			return "", fmt.Errorf("not able to generate new random string")

		}
		b[i] = letterBytes[n.Uint64()]
	}
	return string(b), nil
}

func NewStateStorage(sessionManager *scs.SessionManager) *StateStorage {
	return &StateStorage{
		sessionManager: sessionManager,
	}
}
