SHELL := bash
.SHELLFLAGS = -ec
.ONESHELL:
.DEFAULT_GOAL := help
ifndef VERBOSE
  MAKEFLAGS += --silent
endif

SPIS_TAG_NAME ?= next
SPIS_IMAGE_TAG_BASE ?= quay.io/skabashn/service-provider-integration-oauth
SPIS_IMG ?= $(SPIS_IMAGE_TAG_BASE):$(SPIS_TAG_NAME)

##@ General

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

test: fmt fmt_license vet ## Run the unit tests
	go test ./... -cover

run: ## Run the binary
	go run main.go

vet: fmt fmt_license ## Run go vet against code.
	go vet ./...

##@ Build

build: fmt fmt_license vet ## Builds the binary
	go build -o bin/spi-oauth main.go

docker-build: fmt fmt_license vet ## Builds the docker image. Use the SPI_IMG env var to override the image tag
	docker build -t ${SPIS_IMG} .

docker-push: docker-build ## Pushes the image. Use the SPI_IMG env var to override the image tag
	docker push ${SPIS_IMG}

fmt:
  ifneq ($(shell command -v goimports 2> /dev/null),)
	  find . -not -path '*/\.*' -name '*.go' -exec goimports -w {} \;
  else
	  @echo "WARN: goimports is not installed -- formatting using go fmt instead."
	  @echo "      Please install goimports to ensure file imports are consistent."
	  go fmt -x ./...
  endif

fmt_license:
  ifneq ($(shell command -v addlicense 2> /dev/null),)
	  @echo 'addlicense -v -f license_header.txt **/*.go'
	  addlicense -v -f license_header.txt $$(find . -not -path '*/\.*' -name '*.go')
  else
	  $(error addlicense must be installed for this rule: go get -u github.com/google/addlicense)
  endif
