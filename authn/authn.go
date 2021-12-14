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

package authn

import (
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/redhat-appstudio/service-provider-integration-oauth/config"
	authn "k8s.io/apiserver/pkg/authentication/authenticator"
	authnfactory "k8s.io/apiserver/pkg/authentication/authenticatorfactory"
)

func NewFromConfig(cfg config.Configuration) (authn.Request, error) {
	return New(cfg.KubernetesClient, cfg.KubernetesAuthAudiences)
}

func New(client *kubernetes.Clientset, audiences []string) (authn.Request, error) {
	authConfig := authnfactory.DelegatingAuthenticatorConfig{
		Anonymous:                false,
		TokenAccessReviewClient:  client.AuthenticationV1(),
		TokenAccessReviewTimeout: 0,
		WebhookRetryBackoff:      &wait.Backoff{Duration: 1 * time.Minute, Steps: 10},
		CacheTTL:                 2 * time.Minute,
		APIAudiences:             audiences,
	}

	auth, _, err := authConfig.New()
	if err != nil {
		return nil, err
	}

	return auth, nil
}
