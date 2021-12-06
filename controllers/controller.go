package controllers

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
	"spi-oauth/config"
	"spi-oauth/log"
	"strings"
)

type Controller interface {
	Authenticate(w http.ResponseWriter, r *http.Request)
	Callback(ctx context.Context, w http.ResponseWriter, r *http.Request)
}

func FromConfiguration(configuration config.ServiceProviderConfiguration) (Controller, error) {
	switch configuration.ServiceProviderType {
	case config.ServiceProviderTypeGitHub:
		return &GitHubController{Config: configuration}, nil
	case config.ServiceProviderTypeQuay:
		return nil, fmt.Errorf("not implemented yet")
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

func commonAuthenticate(w http.ResponseWriter, r *http.Request, cfg *config.ServiceProviderConfiguration, endpoint oauth2.Endpoint) {
	oauthCfg := newOAuth2Config(cfg)
	oauthCfg.Endpoint = endpoint
	oauthCfg.Scopes = strings.Split(r.FormValue("scopes"), ",")

	state := r.FormValue("state")
	url := oauthCfg.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusFound)
}

func finishOAuthExchange(ctx context.Context, r *http.Request, cfg *config.ServiceProviderConfiguration, endpoint oauth2.Endpoint) (*oauth2.Token, error) {
	oauthCfg := newOAuth2Config(cfg)
	oauthCfg.Endpoint = endpoint

	code := r.FormValue("code")

	return oauthCfg.Exchange(ctx, code)
}


func logAndWriteResponse(w http.ResponseWriter, msg string, err error) {
	_, _ = fmt.Fprintf(w, msg + ": ", err.Error())
	log.Error(msg, zap.Error(err))
}
