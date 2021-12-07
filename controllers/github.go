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
	"context"
	"fmt"
	"github.com/redhat-appstudio/service-provider-integration-oauth/config"
	"io/ioutil"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/oauth2/github"
)

type GitHubController struct {
	Config config.ServiceProviderConfiguration
}

var _ Controller = (*GitHubController)(nil)

const gitHubUserAPI = "https://api.github.com/user"

func (g GitHubController) Authenticate(w http.ResponseWriter, r *http.Request) {
	commonAuthenticate(w, r, &g.Config, github.Endpoint)
}

func (g GitHubController) Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	token, err := finishOAuthExchange(ctx, r, &g.Config, github.Endpoint)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		logAndWriteResponse(w, "error in GitHub token exchange", err)
		return
	}

	req, err := http.NewRequest("GET", gitHubUserAPI, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logAndWriteResponse(w, "failed to make GitHub request", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logAndWriteResponse(w, "failed to get GitHub user", err)
		return
	}

	defer func() {
		if err := response.Body.Close(); err != nil {
			zap.L().Error("failed to close the response body", zap.Error(err))
		}
	}()

	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logAndWriteResponse(w, "failed to parse GitHub user data", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Oauth Token: %s <br/>", token.AccessToken)
	fmt.Fprintf(w, "User data: %s", string(content))
}
