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
	"net/http"

	"github.com/redhat-appstudio/service-provider-integration-oauth/config"
	"k8s.io/apiserver/pkg/authentication/authenticator"

	"golang.org/x/oauth2/github"
)

type GitHubController struct {
	Config           config.ServiceProviderConfiguration
	JwtSigningSecret []byte
	Authenticator    authenticator.Request
}

var _ Controller = (*GitHubController)(nil)

const gitHubUserAPI = "https://api.github.com/user"

func (g GitHubController) Authenticate(w http.ResponseWriter, r *http.Request) {
	commonAuthenticate(w, r, g.Authenticator, &g.Config, g.JwtSigningSecret, github.Endpoint)
}

func (g GitHubController) Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	token, result, err := finishOAuthExchange(ctx, r, g.Authenticator, &g.Config, g.JwtSigningSecret, github.Endpoint)
	if err != nil {
		logAndWriteResponse(w, http.StatusBadRequest, "error in GitHub token exchange", err)
		return
	}

	if result == oauthFinishK8sAuthRequired {
		logAndWriteResponse(w, http.StatusUnauthorized, "could not authenticate to Kubernetes", err)
		return
	}

	// Retrieve additional data, if needed

	//req, err := http.NewRequest("GET", gitHubUserAPI, nil)
	//if err != nil {
	//	logAndWriteResponse(w, http.StatusInternalServerError, "failed to make GitHub request", err)
	//	return
	//}
	//req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	//client := getOauth2HttpClient(ctx)
	//response, err := client.Do(req)
	//if err != nil {
	//	logAndWriteResponse(w, http.StatusInternalServerError, "failed to get GitHub user", err)
	//	return
	//}
	//
	//defer func() {
	//	if err := response.Body.Close(); err != nil {
	//		zap.L().Error("failed to close the response body", zap.Error(err))
	//	}
	//}()
	//
	//content, err := ioutil.ReadAll(response.Body)
	//if err != nil {
	//	logAndWriteResponse(w, http.StatusInternalServerError, "failed to parse GitHub user data", err)
	//	return
	//}
	w.WriteHeader(http.StatusOK)

	// save the token and data to K8s
	fmt.Fprintf(w, "Oauth Token: %s <br/>", token.AccessToken)
	//fmt.Fprintf(w, "User data: %s", string(content))
}
