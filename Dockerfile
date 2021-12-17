FROM registry.access.redhat.com/ubi8/go-toolset:1.16.7-5 as builder
ENV GOPATH=/go/
USER root

WORKDIR /spi-oauth

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Copy the go sources
COPY main.go main.go
COPY authn/ authn/
COPY controllers/ controllers/

# build service
# Note that we're not running the tests here. Our integration tests depend on a running cluster which would not be
# available in the docker build.
RUN export ARCH="$(uname -m)" && if [[ ${ARCH} == "x86_64" ]]; then export ARCH="amd64"; elif [[ ${ARCH} == "aarch64" ]]; then export ARCH="arm64"; fi && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} go build -a -o spi-oauth main.go

FROM registry.access.redhat.com/ubi8-minimal:8.4-212

COPY --from=builder /spi-oauth/spi-oauth /spi-oauth

WORKDIR /
USER 65532:65532

ENTRYPOINT ["/spi-oauth"]

