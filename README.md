# spi-oauth
Service provider integration OAuth2 microservice.


[![Code Coverage Report](https://github.com/redhat-appstudio/service-provider-integration-oauth/actions/workflows/codecov.yaml/badge.svg)](https://github.com/redhat-appstudio/service-provider-integration-oauth/actions/workflows/codecov.yaml)
[![codecov](https://codecov.io/gh/redhat-appstudio/service-provider-integration-oauth/branch/main/graph/badge.svg?token=kdeoeJcs0A)](https://codecov.io/gh/redhat-appstudio/service-provider-integration-oauth)

### About

OAuth2 protocol is the most commonly used way that allows users to authorize applications to communicate with service providers.
`spi-oauth` to use this protocol to obtain service provider’s access tokens without the need for the user to provide us his login credentials.


This OAuth2 microservice would be responsible for:
 - Initial redirection to the service provider
 - Callback from the service provider
 - Persistence of access token that was received from  the service provider into the permanent backend (k8s secrets or Vault)
 - Handling of negative authorization and error codes
 - Creation or update of SPIAccessToken
 - Successful redirection at the end

### How to build
 `make docker-build docker-push`
  Available paramters
  - `SPIS_IMAGE_TAG_BASE` - the name of the image. Example `quay.io/skabashn/service-provider-integration-oauth`.
  - `SPIS_TAG_NAME` - the tag of the image. Example `$(git branch --show-current)'_'$(date '+%Y_%m_%d_%H_%M_%S')`.
### How to run
The following deployment can be used to run `spi-oauth` microservice

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app.kubernetes.io/name: service-provider-integration-oauth
    app.kubernetes.io/version: 0.2.0
  name: service-provider-integration-oauth
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: service-provider-integration-oauth
      app.kubernetes.io/version: 0.2.0
  template:
    metadata:
      labels:
        app.kubernetes.io/name: service-provider-integration-oauth
        app.kubernetes.io/version: 0.2.0
    spec:
      containers:
        - env:
            - name: KUBERNETES_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          image:  quay.io/skabashn/service-provider-integration-oauth:main_2021_12_16_09_40_57
          imagePullPolicy: Always
          volumeMounts:
          - name: config
            mountPath: "/etc/spi"
            readOnly: true
          livenessProbe:
            failureThreshold: 3
            httpGet:
              path: /health
              port: 8000
              scheme: HTTP
            initialDelaySeconds: 0
            periodSeconds: 30
            successThreshold: 1
            timeoutSeconds: 10
          name: service-provider-integration-oauth
          ports:
            - containerPort: 8000
              name: http
              protocol: TCP
          readinessProbe:
            failureThreshold: 3
            httpGet:
              path: /ready
              port: 8000
              scheme: HTTP
            initialDelaySeconds: 0
            periodSeconds: 30
            successThreshold: 1
            timeoutSeconds: 10
          resources:
            limits:
              cpu: 1000m
              memory: 512Mi
            requests:
              cpu: 250m
              memory: 64Mi
      volumes:
      - name: config
        secret:
          secretName: spi-oauth-config
```
As a prerequisite `spi-oauth-config` Secret has to be created in such form.
```yaml
apiVersion: v1
type: Opaque
kind: Secret
metadata:
  name: spi-oauth-config
  annotations:
data:
  config.yaml: ## base64 config yaml

```
where config.yaml looks like
```yaml
sharedSecretFile: /tmp/over-there
serviceProviders:
- type: GitHub
  clientId: "123"
  clientSecret: "42"
  redirectUrl: https://localhost:8080/github/callback
```