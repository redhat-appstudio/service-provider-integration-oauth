/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var client = &http.Client{
	Timeout: 1 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func TestMain(m *testing.M) {
	os.Setenv("GITHUB_CRED_PATH", "github_test.txt")
	os.Setenv("QUAY_CRED_PATH", "quay_test.txt")
	os.Setenv("PORT", "33800")
	go start()
	time.Sleep(1 * time.Second)
	os.Exit(m.Run())
}

func TestBadRequestUrl(t *testing.T) {

	r, _ := http.NewRequest("GET", "http://localhost:33800/abcd", nil)

	resp, err := client.Do(r)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestGitHubRedirect(t *testing.T) {

	r, _ := http.NewRequest("GET", "http://localhost:33800/github/authenticate", nil)

	resp, err := client.Do(r)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), "https://github.com/login/oauth/authorize"))
}

func TestQuayRedirect(t *testing.T) {

	r, _ := http.NewRequest("GET", "http://localhost:33800/quay/authenticate", nil)

	resp, err := client.Do(r)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), "https://quay.io/oauth/authorize"))
}
