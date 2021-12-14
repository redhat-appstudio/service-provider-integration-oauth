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

	"github.com/redhat-appstudio/service-provider-integration-oauth/authn"
	"github.com/redhat-appstudio/service-provider-integration-oauth/config"
	"github.com/redhat-appstudio/service-provider-integration-oauth/oauthstate"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type Controller interface {
	Authenticate(w http.ResponseWriter, r *http.Request)
	Callback(ctx context.Context, w http.ResponseWriter, r *http.Request)
}

type oauthFinishResult int

const (
	oauthFinishAuthenticated oauthFinishResult = iota
	oauthFinishK8sAuthRequired
	oauthFinishError
)

func FromConfiguration(fullConfig config.Configuration, spConfig config.ServiceProviderConfiguration) (Controller, error) {
	authtor, err := authn.NewFromConfig(fullConfig)
	if err != nil {
		return nil, err
	}

	switch spConfig.ServiceProviderType {
	case config.ServiceProviderTypeGitHub:
		return &GitHubController{Config: spConfig, JwtSigningSecret: fullConfig.SharedSecret, Authenticator: authtor}, nil
	case config.ServiceProviderTypeQuay:
		return &QuayController{Config: spConfig, JwtSigningSecret: fullConfig.SharedSecret, Authenticator: authtor}, nil
	}
	return nil, fmt.Errorf("not implemented yet")
}

func newOAuth2Config(cfg *config.ServiceProviderConfiguration) oauth2.Config {
	return oauth2.Config{
		ClientID:     cfg.ClientId,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectUrl,
	}
}

func commonAuthenticate(w http.ResponseWriter, r *http.Request, auth authenticator.Request, cfg *config.ServiceProviderConfiguration, jwtSecret []byte, endpoint oauth2.Endpoint) {
	stateString := r.FormValue("state")
	codec, err := oauthstate.NewCodec(jwtSecret)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to instantiate OAuth stateString codec", err)
		return
	}

	state, err := codec.ParseAnonymous(stateString)
	if err != nil {
		logAndWriteResponse(w, http.StatusBadRequest, "failed to decode the OAuth state", err)
		return
	}

	// needs to be obtained before AuthenticateRequest call that removes it from the request!
	authorizationHeader := r.Header.Get("Authorization")

	authResponse, _, err := auth.AuthenticateRequest(r)
	if err != nil {
		logAndWriteResponse(w, http.StatusUnauthorized, "failed to authenticate the request in Kubernetes", err)
		return
	}

	identity := user.DefaultInfo{
		Name:   authResponse.User.GetName(),
		UID:    authResponse.User.GetUID(),
		Groups: authResponse.User.GetGroups(),
		Extra:  authResponse.User.GetExtra(),
	}
	authedState := oauthstate.AuthenticatedOAuthState{
		AnonymousOAuthState: state,
		KubernetesIdentity:  identity,
		AuthorizationHeader: authorizationHeader,
	}

	oauthCfg := newOAuth2Config(cfg)
	oauthCfg.Endpoint = endpoint
	oauthCfg.Scopes = authedState.Scopes

	stateString, err = codec.EncodeAuthenticated(&authedState)
	if err != nil {
		logAndWriteResponse(w, http.StatusInternalServerError, "failed to encode OAuth state", err)
	}

	url := oauthCfg.AuthCodeURL(stateString)

	http.Redirect(w, r, url, http.StatusFound)
}

func finishOAuthExchange(ctx context.Context, r *http.Request, auth authenticator.Request, cfg *config.ServiceProviderConfiguration, jwtSecret []byte, endpoint oauth2.Endpoint) (*oauth2.Token, oauthFinishResult, error) {
	// TODO support the implicit flow here, too?

	// check that the state is correct
	stateString := r.FormValue("state")
	codec, err := oauthstate.NewCodec(jwtSecret)
	if err != nil {
		return nil, oauthFinishError, err
	}

	state, err := codec.ParseAuthenticated(stateString)
	if err != nil {
		return nil, oauthFinishError, err
	}

	r.Header.Set("Authorization", state.AuthorizationHeader)

	authResponse, _, err := auth.AuthenticateRequest(r)
	if err != nil {
		return nil, oauthFinishError, err
	}

	if state.KubernetesIdentity.Name != authResponse.User.GetName() ||
		!equalMapOfSlicesUnordered(state.KubernetesIdentity.Extra, authResponse.User.GetExtra()) ||
		state.KubernetesIdentity.UID != authResponse.User.GetUID() ||
		!equalSliceUnOrdered(state.KubernetesIdentity.Groups, authResponse.User.GetGroups()) {

		return nil, oauthFinishK8sAuthRequired, fmt.Errorf("kubernetes identity doesn't match after completing the OAuth flow")
	}

	// the state is ok, let's retrieve the token from the service provider
	oauthCfg := newOAuth2Config(cfg)
	oauthCfg.Endpoint = endpoint

	code := r.FormValue("code")

	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		return nil, oauthFinishError, err
	}
	return token, oauthFinishAuthenticated, nil
}

func logAndWriteResponse(w http.ResponseWriter, status int, msg string, err error) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, msg+": ", err.Error())
	zap.L().Error(msg, zap.Error(err))
}

func equalMapOfSlicesUnordered(a map[string][]string, b map[string][]string) bool {
	for k, v := range a {
		if !equalSliceUnOrdered(v, b[k]) {
			return false
		}
	}

	return true
}

func equalSliceUnOrdered(as []string, bs []string) bool {
	if len(as) != len(bs) {
		return false
	}

as:
	for _, a := range as {
		for _, b := range bs {
			if a == b {
				continue as
			}
		}

		return false
	}

	return true
}

// getOauth2HttpClient tries to find the HTTP client used by the OAuth2 library in the context.
// This is useful mainly in tests where we can use mocked responses even for our own calls.
func getOauth2HttpClient(ctx context.Context) *http.Client {
	cl, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if cl != nil {
		return cl
	}

	return &http.Client{}
}
