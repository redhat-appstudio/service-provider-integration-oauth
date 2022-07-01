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
	"errors"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/brianvoe/gofakeit/v6"
	"go.uber.org/zap"
)

type StateStorage struct {
	sessionManager *scs.SessionManager
}

var (
	// Uses math/rand(Pseudo) with mutex locking
	faker = gofakeit.NewCrypto()
)

func (storage StateStorage) VeilRealState(req *http.Request) (string, error) {
	state := req.URL.Query().Get("state")
	if state == "" {
		zap.L().Error("Request has no state parameter")
		return "", errors.New("request has no `state` parameter")
	}
	newState := faker.Regex("([0-9a-z]){32}")
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

func NewStateStorage(sessionManager *scs.SessionManager) *StateStorage {
	return &StateStorage{
		sessionManager: sessionManager,
	}
}
