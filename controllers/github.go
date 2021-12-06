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
	"golang.org/x/oauth2/github"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var gitHubConf *oauth2.Config

func initGitHubConfig(w http.ResponseWriter) bool {
	filename := "github.txt"
	if value, ok := os.LookupEnv("GITHUB_CRED_PATH"); ok {
		filename = value
	}
	credential, err := readCredsFile(filename)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read GitHub credential file: %s", err.Error()), http.StatusInternalServerError)
		return false
	}
	gitHubConf = &oauth2.Config{
		ClientID:     credential.clientId,
		ClientSecret: credential.clientSecret,
		RedirectURL:  credential.redirectURL,
		Endpoint:     github.Endpoint,
	}
	return true
}

const gitHubUserAPI = "https://api.github.com/user?access_token="

var GitHubAuthenticate = func(w http.ResponseWriter, r *http.Request) {

	if gitHubConf == nil && !initGitHubConfig(w) {
		return
	}

	scopes := r.FormValue("scopes")
	gitHubConf.Scopes = strings.Split(scopes, ",")

	state := r.FormValue("state")
	url := gitHubConf.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusFound)
}

var GitHubCallback = func(w http.ResponseWriter, r *http.Request) {

	if gitHubConf == nil && !initGitHubConfig(w) {
		return
	}

	//state := r.FormValue("state");
	//TODO: validate state
	code := r.FormValue("code")

	token, err := gitHubConf.Exchange(context.Background(), code)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error in GitHub token exchange: %s", err.Error())
		return
	}

	req, err := http.NewRequest("GET", gitHubUserAPI, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed making GitHub request: %s", err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed getting GitHub user: %s", err.Error())
		return
	}

	defer response.Body.Close()
	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Failed pasring GitHub user data: %s", err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Oauth Token: %s <br/>", token.AccessToken)
	fmt.Fprintf(w, "User data: %s", string(content))

}
