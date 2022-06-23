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
	"fmt"
)

var (
	NoBearerTokenError             = errors.New("no bearer token found")
	EmptyOrOmittedAccessTokenError = errors.New("access token can't be omitted or empty")
)

type SPIAccessTokenFetchError struct {
	TokenObjectNamespace string
	TokenObjectName      string
	Cause                error
}

func (e *SPIAccessTokenFetchError) Error() string {
	return fmt.Sprintf("failed to get SPIAccessToken object %s/%s: %s", e.TokenObjectNamespace, e.TokenObjectName, e.Cause)
}

func (e *SPIAccessTokenFetchError) Unwrap() error {
	return e.Cause
}

type JsonParseError struct {
	Cause error
}

func (e *JsonParseError) Error() string {
	return fmt.Sprintf("failed to decode request body as token JSON: %s", e.Cause)
}

func (e *JsonParseError) Unwrap() error {
	return e.Cause
}

type TokenStorageSaveError struct {
	Cause error
}

func (e *TokenStorageSaveError) Error() string {
	return fmt.Sprintf("failed to store the token data into storage: %s", e.Cause)
}

func (e *TokenStorageSaveError) Unwrap() error {
	return e.Cause
}
