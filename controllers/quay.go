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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"go.uber.org/zap"

	"golang.org/x/oauth2"
)

const quayUserAPI = "https://quay.io/api/v1/user"

// quayEndpoint is the OAuth endpoints specification of quay.io
var quayEndpoint = oauth2.Endpoint{
	AuthURL:  "https://quay.io/oauth/authorize",
	TokenURL: "https://quay.io/oauth/access_token",
}

// retrieveQuayUserDetails reads the user details from the Quay API. Note that Quay doesn't really have a notion
// of user ID.s
func retrieveQuayUserDetails(client *http.Client, token *oauth2.Token) (*v1beta1.TokenMetadata, error) {
	req, err := http.NewRequest("GET", quayUserAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := response.Body.Close(); err != nil {
			zap.L().Error("failed to close the response body", zap.Error(err))
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve user details from Quay")
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	content := map[string]interface{}{}

	if err = json.Unmarshal(data, &content); err != nil {
		return nil, err
	}

	var username string
	if u, ok := content["username"]; ok {
		username = u.(string)
	} else {
		return nil, fmt.Errorf("failed to determine the user name from the Quay response")
	}

	return &v1beta1.TokenMetadata{
		UserName: username,
	}, nil
}
