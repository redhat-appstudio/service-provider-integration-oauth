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

	"golang.org/x/oauth2"
)

type QuayController struct {
	Config           config.ServiceProviderConfiguration
	JwtSigningSecret []byte
	Authenticator    authenticator.Request
}

var _ Controller = (*QuayController)(nil)

const quayUserAPI = "https://quay.io/api/v1/user"

var quayEndpoint = oauth2.Endpoint{
	AuthURL:  "https://quay.io/oauth/authorize",
	TokenURL: "https://quay.io/oauth/token",
}

func (q QuayController) Authenticate(w http.ResponseWriter, r *http.Request) {
	commonAuthenticate(w, r, q.Authenticator, &q.Config, q.JwtSigningSecret, quayEndpoint)
}

func (q QuayController) Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	token, result, err := finishOAuthExchange(ctx, r, q.Authenticator, &q.Config, q.JwtSigningSecret, quayEndpoint)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "error in Quay token exchange", err)
		return
	}

	if result == oauthFinishK8sAuthRequired {
		logAndWriteResponse(w, http.StatusUnauthorized, "could not authenticate to Kubernetes", err)
		return
	}

	// Retrieve additional data, if needed

	//req, err := http.NewRequest("GET", quayUserAPI, nil)
	//if err != nil {
	//	logAndWriteResponse(w, http.StatusInternalServerError, "failed making Quay request", err)
	//	return
	//}
	//req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	//client := &http.Client{}
	//response, err := client.Do(req)
	//if err != nil {
	//	logAndWriteResponse(w, http.StatusInternalServerError, "failed getting Quay user", err)
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
	//	logAndWriteResponse(w, http.StatusInternalServerError, "failed parsing Quay user data", err)
	//	return
	//}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Oauth Token: %s", token.AccessToken)
	//fmt.Fprintf(w, "User data: %s", string(content))
}
