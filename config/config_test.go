package config

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	yaml := `
sharedSecretFile: /tmp/over-there
serviceProviders:
- type: GitHub
  clientId: "123"
  clientSecret: "42"
  redirectUrl: https://localhost:8080/github/callback
- type: Quay
  clientId: "456"
  clientSecret: "54"
  redirectUrl: https://localhost:8080/quay/callback
`

	_, err := ReadFrom(strings.NewReader(yaml))

	assert.NoError(t, err)
}
