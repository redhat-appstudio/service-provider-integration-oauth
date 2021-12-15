module github.com/redhat-appstudio/service-provider-integration-oauth

go 1.16

require (
	github.com/alexflint/go-arg v1.4.2
	github.com/go-jose/go-jose/v3 v3.0.0
	github.com/gorilla/mux v1.8.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.17.0
	github.com/redhat-appstudio/service-provider-integration-operator v0.0.0
	go.uber.org/zap v1.19.1
	golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	k8s.io/api v0.22.4
	k8s.io/apimachinery v0.22.4
	k8s.io/apiserver v0.22.4
	k8s.io/client-go v0.22.4
	k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a
	sigs.k8s.io/controller-runtime v0.10.3
)

replace github.com/redhat-appstudio/service-provider-integration-operator => github.com/metlos/service-provider-integration-operator v0.0.0-20211215151911-14409bda9146
