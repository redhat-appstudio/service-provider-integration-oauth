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

	api "github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type TokenUploader interface {
	Upload(ctx context.Context, tokenObjectName string, tokenObjectNamespace string, data *api.Token) error
}

type UploadFunc func(ctx context.Context, tokenObjectName string, tokenObjectNamespace string, data *api.Token) error

func (u UploadFunc) Upload(ctx context.Context, tokenObjectName string, tokenObjectNamespace string, data *api.Token) error {
	return u(ctx, tokenObjectName, tokenObjectNamespace, data)
}

type SpiTokenUploader struct {
	K8sClient client.Client
	Storage   tokenstorage.TokenStorage
}

func (u *SpiTokenUploader) Upload(ctx context.Context, tokenObjectName string, tokenObjectNamespace string, data *api.Token) error {
	token := &api.SPIAccessToken{}
	if err := u.K8sClient.Get(ctx, client.ObjectKey{Name: tokenObjectName, Namespace: tokenObjectNamespace}, token); err != nil {
		return fmt.Errorf("failed to get SPIAccessToken object %s/%s: %w", tokenObjectName, tokenObjectNamespace, err)
	}

	if err := u.Storage.Store(ctx, token, data); err != nil {
		return fmt.Errorf("failed to store the token data into storage: %w", err)
	}
	return nil
}
