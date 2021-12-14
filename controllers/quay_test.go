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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/redhat-appstudio/service-provider-integration-oauth/authn"
	"github.com/redhat-appstudio/service-provider-integration-oauth/oauthstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/redhat-appstudio/service-provider-integration-oauth/config"

	"github.com/go-jose/go-jose/v3/json"
	"golang.org/x/oauth2"
)

var _ = Describe("GitHub Controller", func() {

	prepareAnonymousState := func() string {
		codec, err := oauthstate.NewCodec([]byte("secret"))
		Expect(err).NotTo(HaveOccurred())

		ret, err := codec.EncodeAnonymous(&oauthstate.AnonymousOAuthState{
			TokenName:           "tokenName",
			TokenNamespace:      "default",
			IssuedAt:            time.Now().Unix(),
			Scopes:              []string{"a", "b"},
			ServiceProviderType: "Quay",
			ServiceProviderUrl:  "https://quay.io",
		})
		Expect(err).NotTo(HaveOccurred())
		return ret
	}

	grabK8sToken := func() string {
		var secrets *corev1.SecretList

		Eventually(func(g Gomega) {
			var err error
			secrets, err = IT.Client.CoreV1().Secrets(IT.Namespace).List(context.TODO(), metav1.ListOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(secrets.Items).NotTo(BeEmpty())
		}).Should(Succeed())

		for _, s := range secrets.Items {
			if s.Annotations["kubernetes.io/service-account.name"] == "default" {
				return string(s.Data["token"])
			}
		}

		Fail("Could not find the token of the default service account in the test namespace", 1)
		return ""
	}

	prepareController := func() *QuayController {
		auth, err := authn.New(IT.Client, []string{})
		Expect(err).NotTo(HaveOccurred())

		return &QuayController{
			Config: config.ServiceProviderConfiguration{
				ClientId:     "clientId",
				ClientSecret: "clientSecret",
				RedirectUrl:  "http://redirect.url",
			},
			JwtSigningSecret: []byte("secret"),
			Authenticator:    auth,
		}
	}

	authenticateFlow := func() (*QuayController, *httptest.ResponseRecorder) {
		token := grabK8sToken()

		// This is the setup for the HTTP call to /github/authenticate
		req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s&scopes=a,b", prepareAnonymousState()), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		q := prepareController()

		q.Authenticate(res, req)

		return q, res
	}

	It("redirects to Quay OAuth URL with state and scopes", func() {
		_, res := authenticateFlow()

		Expect(res.Code).To(Equal(http.StatusFound))

		redirect, err := url.Parse(res.Header().Get("Location"))
		Expect(err).NotTo(HaveOccurred())
		Expect(redirect.Scheme).To(Equal("https"))
		Expect(redirect.Host).To(Equal("quay.io"))
		Expect(redirect.Path).To(Equal("/oauth/authorize"))
		Expect(redirect.Query().Get("client_id")).To(Equal("clientId"))
		Expect(redirect.Query().Get("redirect_uri")).To(Equal("http://redirect.url"))
		Expect(redirect.Query().Get("response_type")).To(Equal("code"))
		Expect(redirect.Query().Get("state")).NotTo(BeEmpty())
		Expect(redirect.Query().Get("scope")).To(Equal("a b"))
	})

	When("OAuth initiated", func() {
		It("exchanges the code for token", func() {
			g, res := authenticateFlow()

			// grab the encoded state
			redirect, err := url.Parse(res.Header().Get("Location"))
			Expect(err).NotTo(HaveOccurred())
			state := redirect.Query().Get("state")

			// simulate github redirecting back to our callback endpoint...
			req := httptest.NewRequest("GET", fmt.Sprintf("/?state=%s&code=123", state), nil)
			res = httptest.NewRecorder()

			// The callback handler will be reaching out to github to exchange the code for the token.. let's fake that
			// response...
			bakedResponse, _ := json.Marshal(oauth2.Token{
				AccessToken:  "token",
				TokenType:    "jwt",
				RefreshToken: "refresh",
				Expiry:       time.Now(),
			})
			githubReached := false
			ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, &http.Client{
				Transport: fakeRoundTrip(func(r *http.Request) (*http.Response, error) {
					if strings.HasPrefix(r.URL.String(), "https://quay.io") {
						githubReached = true
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{},
							Body:       ioutil.NopCloser(bytes.NewBuffer(bakedResponse)),
							Request:    r,
						}, nil
					}

					return nil, fmt.Errorf("unexpected request to: %s", r.URL.String())
				}),
			})

			g.Callback(ctx, res, req)

			Expect(res.Code).To(Equal(http.StatusOK))
			Expect(githubReached).To(BeTrue())
		})
	})
})
