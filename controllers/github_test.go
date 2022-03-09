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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestTokenSentWhenRetrievingGitHubUserDetails(t *testing.T) {
	bakedResponse, _ := json.Marshal(map[string]interface{}{
		"id":    123,
		"login": "mylogin",
	})

	githubReached := false
	authorizationSet := false

	metadata, err := retrieveGitHubUserDetails(&http.Client{
		Transport: fakeRoundTrip(func(r *http.Request) (*http.Response, error) {
			if strings.HasPrefix(r.URL.String(), "https://api.github.com/user") {
				githubReached = true

				authorizationSet = r.Header.Get("Authorization") == "Bearer tkn"

				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{},
					Body:       ioutil.NopCloser(bytes.NewBuffer(bakedResponse)),
					Request:    r,
				}, nil
			}

			return nil, fmt.Errorf("unexpected request to: %s", r.URL.String())
		}),
	}, &oauth2.Token{
		AccessToken:  "tkn",
		TokenType:    "asdf",
		RefreshToken: "rtkn",
		Expiry:       time.Now(),
	})

	assert.NoError(t, err)
	assert.True(t, githubReached)
	assert.True(t, authorizationSet)
	assert.Equal(t, "123", metadata.UserId)
	assert.Equal(t, "mylogin", metadata.Username)
}
