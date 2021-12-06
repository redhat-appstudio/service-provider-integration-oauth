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

package oauthstate

import (
	"github.com/go-jose/go-jose/v3/jwt"
)

type AuthenticatedOAuthState struct {
	AnonymousOAuthState
	KubernetesIdentityToken string `json:"k8sIdentity"`
}

func (s *Codec) AuthenticatedStateFor(anonymous *AnonymousOAuthState, identityToken string) (string, error) {
	return jwt.Signed(s.signer).Claims(&AuthenticatedOAuthState{
		AnonymousOAuthState:     *anonymous,
		KubernetesIdentityToken: identityToken,
	}).CompactSerialize()
}

func (s *Codec) ParseAuthenticatedState(state string) (AuthenticatedOAuthState, error) {
	token, err := jwt.ParseSigned(state)
	if err != nil {
		return AuthenticatedOAuthState{}, err
	}

	parsedState := AuthenticatedOAuthState{}
	if err := token.Claims(s.signingSecret, &parsedState); err != nil {
		return AuthenticatedOAuthState{}, err
	}

	if err := validateAnonymousState(&parsedState.AnonymousOAuthState); err != nil {
		return AuthenticatedOAuthState{}, err
	}

	return parsedState, nil
}
