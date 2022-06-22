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
	tokenObjectNamespace string
	tokenObjectName      string
	cause                error
}

func (e *SPIAccessTokenFetchError) Error() string {
	return fmt.Sprintf("failed to get SPIAccessToken object %s/%s: %s", e.tokenObjectNamespace, e.tokenObjectName, e.cause)
}

type JsonParseError struct {
	cause error
}

func (e *JsonParseError) Error() string {
	return fmt.Sprintf("failed to decode request body as token JSON: %s", e.cause)
}

type TokenStorageSaveError struct {
	cause error
}

func (e *TokenStorageSaveError) Error() string {
	return fmt.Sprintf("failed to store the token data into storage: %s", e.cause)
}
