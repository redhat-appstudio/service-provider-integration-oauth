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

	"github.com/alexedwards/scs"
	"go.uber.org/zap"
)

type Authenticator struct {
	K8sClient      AuthenticatingClient
	SessionManager *scs.Manager
}

func (a Authenticator) tokenReview(token string, req *http.Request) (bool, error) {
	//TODO not working. temporary disabled.
	//review := v1.TokenReview{
	//	Spec: v1.TokenReviewSpec{
	//		Token: token,
	//	},
	//}
	//
	//ctx := WithAuthIntoContext(token, req.Context())
	//
	//if err := a.K8sClient.Create(ctx, &review); err != nil {
	//	zap.L().Error("token review error", zap.Error(err))
	//	return false, err
	//}
	//
	//zap.L().Debug("token review result", zap.Stringer("review", &review))
	//return review.Status.Authenticated, nil
	return true, nil
}
func (a *Authenticator) GetToken(r *http.Request) (string, error) {
	zap.L().Debug("/GetToken")
	session := a.SessionManager.Load(r)
	token, err := session.GetString("k8s_token")
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("no token associated with the given session")
	}
	return token, nil
}

func (a Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	zap.L().Debug("/login")

	session := a.SessionManager.Load(r)

	token := r.FormValue("k8s_token")

	if token == "" {
		token = ExtractTokenFromAuthorizationHeader(r.Header.Get("Authorization"))
	}

	if token == "" {
		zap.L().Warn("Undesired usage of k8s_token as query parameter. Please consider to use Authorization header instead of query parameter.")
		logDebugAndWriteResponse(w, http.StatusUnauthorized, "failed extract authorization info either from headers or form/query parameters")
		return
	}
	hasAccess, err := a.tokenReview(token, r)
	if err != nil {
		logErrorAndWriteResponse(w, http.StatusUnauthorized, "failed to determine if the authenticated user has access", err)
		zap.L().Warn("The token is incorrect or the SPI OAuth service is not configured properly " +
			"and the API_SERVER environment variable points it to the incorrect Kubernetes API server. " +
			"If SPI is running with Devsandbox Proxy or KCP, make sure this env var points to the Kubernetes API proxy," +
			" otherwise unset this variable. See more https://github.com/redhat-appstudio/infra-deployments/pull/264")
		return
	}

	if !hasAccess {
		logDebugAndWriteResponse(w, http.StatusUnauthorized, "authenticating the request in Kubernetes unsuccessful")
		return
	}

	if err := session.PutString(w, "k8s_token", token); err != nil {
		logErrorAndWriteResponse(w, http.StatusInternalServerError, "failed to persist session data", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	zap.L().Debug("/login ok")
}

func NewAuthenticator(sessionManager *scs.Manager, cl AuthenticatingClient) *Authenticator {
	return &Authenticator{
		K8sClient:      cl,
		SessionManager: sessionManager,
	}
}
