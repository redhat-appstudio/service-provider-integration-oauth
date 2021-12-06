package controllers

import (
	"bytes"
	"context"
	"fmt"
	"github.com/go-jose/go-jose/v3/json"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"spi-oauth/config"
	"strings"
	"testing"
	"time"
)

func TestGitHubAuthenticateRedirect(t *testing.T) {
	g := GitHubController{
		Config: config.ServiceProviderConfiguration{
			ClientId:     "clientId",
			ClientSecret: "clientSecret",
			RedirectUrl:  "http://redirect.url",
		},
	}

	req := httptest.NewRequest("GET", "/?state=state&scopes=a,b", nil)
	res := httptest.NewRecorder()

	g.Authenticate(res, req)

	assert.Equal(t, res.Code, http.StatusFound)

	redirect, err := url.Parse(res.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "https", redirect.Scheme)
	assert.Equal(t, "github.com", redirect.Host)
	assert.Equal(t, "/login/oauth/authorize", redirect.Path)
	assert.Equal(t, "clientId", redirect.Query().Get("client_id"))
	assert.Equal(t, "http://redirect.url", redirect.Query().Get("redirect_uri"))
	assert.Equal(t, "code", redirect.Query().Get("response_type"))
	assert.Equal(t, "state", redirect.Query().Get("state"))
	assert.Equal(t, "a b", redirect.Query().Get("scope"))
}

func TestGitHubCallbackReachesOutForToken(t *testing.T) {
	g := GitHubController{
		Config: config.ServiceProviderConfiguration{
			ClientId:     "clientId",
			ClientSecret: "clientSecret",
			RedirectUrl:  "http://redirect.url",
		},
	}

	req := httptest.NewRequest("GET", "/?state=state&scopes=a,b", nil)
	res := httptest.NewRecorder()

	bakedResponse, _ := json.Marshal(oauth2.Token{
		AccessToken:  "token",
		TokenType:    "jwt",
		RefreshToken: "refresh",
		Expiry:       time.Now(),
	})

	githubReached := false

	ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, &http.Client{
		Transport: fakeRoundTrip(func(r *http.Request) (*http.Response, error) {
			if strings.HasPrefix(r.URL.String(), "https://github.com") {
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

	assert.True(t, githubReached)
	// TODO finish this test once we write the token somewhere
}
