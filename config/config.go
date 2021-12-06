package config

import (
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"os"
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
