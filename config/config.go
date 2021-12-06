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

package config

import (
	"io"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

type ServiceProviderType string

const (
	ServiceProviderTypeGitHub ServiceProviderType = "GitHub"
	ServiceProviderTypeQuay   ServiceProviderType = "Quay"
)

type ServiceProviderConfiguration struct {
	ClientId               string              `yaml:"clientId"`
	ClientSecret           string              `yaml:"clientSecret"`
	RedirectUrl            string              `yaml:"redirectUrl"`
	ServiceProviderType    ServiceProviderType `yaml:"type"`
	ServiceProviderBaseUrl string              `yaml:"baseUrl,omitempty"`
}

// Configuration contains the specification of the known service providers as well as other configuration data shared
// between the SPI OAuth service and the SPI operator
type Configuration struct {
	ServiceProviders []ServiceProviderConfiguration `yaml:"serviceProviders"`
	SharedSecretFile string                         `yaml:"sharedSecretFile"`
}

func LoadFrom(path string) (Configuration, error) {
	file, err := os.Open(path)
	if err != nil {
		return Configuration{}, err
	}
	defer file.Close()

	return ReadFrom(file)
}

func ReadFrom(rdr io.Reader) (Configuration, error) {
	ret := Configuration{}

	bytes, err := ioutil.ReadAll(rdr)
	if err != nil {
		return ret, err
	}

	if err := yaml.Unmarshal(bytes, &ret); err != nil {
		return ret, err
	}

	return ret, nil
}
