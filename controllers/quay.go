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

package controllers

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var quayConf *oauth2.Config

var quayEndpoint = oauth2.Endpoint{
	AuthURL:  "https://quay.io/oauth/authorize",
	TokenURL: "https://quay.io/oauth/token",
}

func initQuayConfig(w http.ResponseWriter) bool {
	filename := "quay.txt"
	if value, ok := os.LookupEnv("QUAY_CRED_PATH"); ok {
		filename = value
	}
	credential, err := readCredsFile(filename)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read Quay credential file: %s", err.Error()), http.StatusInternalServerError)
		return false
	}
	quayConf = &oauth2.Config{
		ClientID:     credential.clientId,
		ClientSecret: credential.clientSecret,
		RedirectURL:  credential.redirectURL,
		Endpoint:     quayEndpoint,
	}
	return true
}

const quayUserAPI = "https://quay.io/api/v1/user"

var QuayAuthenticate = func(w http.ResponseWriter, r *http.Request) {

	if quayConf == nil && !initQuayConfig(w) {
		return
	}

	scopes := r.FormValue("scopes")
	quayConf.Scopes = strings.Split(scopes, ",")

	state := r.FormValue("state")

	//	typeOption := oauth2.SetAuthURLParam("response_type", "code")
	//	realmOption := oauth2.SetAuthURLParam("realm", "realm")
	url := quayConf.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusFound)
}

var QuayCallback = func(w http.ResponseWriter, r *http.Request) {

	if quayConf == nil && !initQuayConfig(w) {
		return
	}

	//state := r.FormValue("state");
	//TODO: validate state

	code := r.FormValue("code")

	token, err := quayConf.Exchange(context.Background(), code)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error in Quay token exchange: %s", err.Error())
		return
	}

	req, err := http.NewRequest("GET", quayUserAPI, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed making Quay request: %s", err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed getting Quay user: %s", err.Error())
		return
	}
	defer response.Body.Close()
	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed pasring Quay user data: %s", err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Oauth Token: %s", token.AccessToken)
	fmt.Fprintf(w, "User data: %s", string(content))

}
