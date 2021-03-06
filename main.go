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

package main

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/logs"

	"github.com/alexedwards/scs/v2/memstore"
	"github.com/alexflint/go-arg"
	"github.com/gorilla/mux"
	"github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/config"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"go.uber.org/zap"
	authz "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/redhat-appstudio/service-provider-integration-oauth/controllers"
)

type cliArgs struct {
	ConfigFile                     string                       `arg:"-c, --config-file, env" default:"/etc/spi/config.yaml" help:"The location of the configuration file"`
	ServiceAddr                    string                       `arg:"-b, --service-addr, env" default:"0.0.0.0:8000" help:"Service address to listen on"`
	AllowedOrigins                 string                       `arg:"-o, --allowed-origins, env" default:"https://console.dev.redhat.com,https://prod.foo.redhat.com:1337" help:"Comma-separated list of domains allowed for cross-domain requests"`
	KubeConfig                     string                       `arg:"-k, --kubeconfig, env" default:"" help:""`
	KubeInsecureTLS                bool                         `arg:"-f, --kube-insecure-tls, env" default:"false" help:"Whether is allowed or not insecure kubernetes tls connection."`
	ApiServer                      string                       `arg:"-a, --api-server, env:API_SERVER" default:"" help:"host:port of the Kubernetes API server to use when handling HTTP requests"`
	ApiServerCAPath                string                       `arg:"-t, --ca-path, env:API_SERVER_CA_PATH" default:"" help:"the path to the CA certificate to use when connecting to the Kubernetes API server"`
	VaultHost                      string                       `arg:"--vault-host, env" default:"http://spi-vault:8200" help:"Vault host URL. Default is internal kubernetes service."`
	VaultInsecureTLS               bool                         `arg:"-i, --vault-insecure-tls, env" default:"false" help:"Whether is allowed or not insecure vault tls connection."`
	VaultAuthMethod                tokenstorage.VaultAuthMethod `arg:"--vault-auth-method, env" default:"kubernetes" help:"Authentication method to Vault token storage. Options: 'kubernetes', 'approle'."`
	VaultApproleRoleIdFilePath     string                       `arg:"--vault-roleid-filepath, env" default:"/etc/spi/role_id" help:"Used with Vault approle authentication. Filepath with role_id."`
	VaultApproleSecretIdFilePath   string                       `arg:"--vault-secretid-filepath, env" default:"/etc/spi/secret_id" help:"Used with Vault approle authentication. Filepath with secret_id."`
	VaultKubernetesSATokenFilePath string                       `arg:"--vault-k8s-sa-token-filepath, env" help:"Used with Vault kubernetes authentication. Filepath to kubernetes ServiceAccount token. When empty, Vault configuration uses default k8s path. No need to set when running in k8s deployment, useful mostly for local development."`
	VaultKubernetesRole            string                       `arg:"--vault-k8s-role, env" default:"spi-oauth" help:"Used with Vault kubernetes authentication. Vault authentication role set for k8s ServiceAccount."`
	ZapDevel                       bool                         `arg:"-d, --zap-devel, env" default:"false" help:"Development Mode defaults(encoder=consoleEncoder,logLevel=Debug,stackTraceLevel=Warn) Production Mode defaults(encoder=jsonEncoder,logLevel=Info,stackTraceLevel=Error)"`
	ZapEncoder                     string                       `arg:"-e, --zap-encoder, env" default:"" help:"Zap log encoding (???json??? or ???console???)"`
	ZapLogLevel                    string                       `arg:"-v, --zap-log-level, env" default:"" help:"Zap Level to configure the verbosity of logging"`
	ZapStackTraceLevel             string                       `arg:"-s, --zap-stacktrace-level, env" default:"" help:"Zap Level at and above which stacktraces are captured"`
	ZapTimeEncoding                string                       `arg:"-t, --zap-time-encoding, env" default:"rfc3339" help:"one of 'epoch', 'millis', 'nano', 'iso8601', 'rfc3339' or 'rfc3339nano'"`
}

func main() {
	args := cliArgs{}
	arg.MustParse(&args)

	logs.InitLoggers(args.ZapDevel, args.ZapEncoder, args.ZapLogLevel, args.ZapStackTraceLevel, args.ZapTimeEncoding)

	zap.L().Info("Starting OAuth service with environment", zap.Strings("env", os.Environ()), zap.Any("configuration", &args))

	cfg, err := config.LoadFrom(args.ConfigFile)
	if err != nil {
		zap.L().Error("failed to initialize the configuration", zap.Error(err))
		os.Exit(1)
	}

	kubeConfig, err := kubernetesConfig(&args)
	if err != nil {
		zap.L().Error("failed to create kubernetes configuration", zap.Error(err))
		os.Exit(1)
	}

	router := mux.NewRouter()

	// insecure mode only allowed when the trusted root certificate is not specified...
	if args.KubeInsecureTLS && kubeConfig.TLSClientConfig.CAFile == "" {
		kubeConfig.Insecure = true
	}

	// we can't use the default dynamic rest mapper, because we don't have a token that would enable us to connect
	// to the cluster just yet. Therefore, we need to list all the resources that we are ever going to query using our
	// client here thus making the mapper not reach out to the target cluster at all.
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{})
	mapper.Add(authz.SchemeGroupVersion.WithKind("SelfSubjectAccessReview"), meta.RESTScopeRoot)
	//	mapper.Add(auth.SchemeGroupVersion.WithKind("TokenReview"), meta.RESTScopeRoot)
	mapper.Add(v1beta1.GroupVersion.WithKind("SPIAccessToken"), meta.RESTScopeNamespace)
	mapper.Add(v1beta1.GroupVersion.WithKind("SPIAccessTokenDataUpdate"), meta.RESTScopeNamespace)

	cl, err := controllers.CreateClient(kubeConfig, client.Options{
		Mapper: mapper,
	})

	if err != nil {
		zap.L().Error("failed to create kubernetes client", zap.Error(err))
		return
	}

	strg, err := tokenstorage.NewVaultStorage(&tokenstorage.VaultStorageConfig{
		Host:                        args.VaultHost,
		AuthType:                    args.VaultAuthMethod,
		Insecure:                    args.VaultInsecureTLS,
		Role:                        args.VaultKubernetesRole,
		ServiceAccountTokenFilePath: args.VaultKubernetesSATokenFilePath,
		RoleIdFilePath:              args.VaultApproleRoleIdFilePath,
		SecretIdFilePath:            args.VaultApproleSecretIdFilePath,
	})
	if err != nil {
		zap.L().Error("failed to create token storage interface", zap.Error(err))
		return
	}

	tokenUploader := controllers.SpiTokenUploader{
		K8sClient: cl,
		Storage: tokenstorage.NotifyingTokenStorage{
			Client:       cl,
			TokenStorage: strg,
		},
	}

	// the session has 15 minutes timeout and stale sessions are cleaned every 5 minutes
	sessionManager := scs.New()
	sessionManager.Store = memstore.NewWithCleanupInterval(5 * time.Minute)
	sessionManager.IdleTimeout = 15 * time.Minute
	sessionManager.Cookie.Name = "appstudio_spi_session"
	sessionManager.Cookie.SameSite = http.SameSiteNoneMode
	sessionManager.Cookie.Secure = true
	authenticator := controllers.NewAuthenticator(sessionManager, cl)
	stateStorage := controllers.NewStateStorage(sessionManager)
	//static routes first
	router.HandleFunc("/health", controllers.OkHandler).Methods("GET")
	router.HandleFunc("/ready", controllers.OkHandler).Methods("GET")
	router.HandleFunc("/callback_success", controllers.CallbackSuccessHandler).Methods("GET")
	router.HandleFunc("/login", authenticator.Login).Methods("POST")
	router.NewRoute().Path("/{type}/callback").Queries("error", "", "error_description", "").HandlerFunc(controllers.CallbackErrorHandler)
	router.NewRoute().Path("/token/{namespace}/{name}").HandlerFunc(controllers.HandleUpload(&tokenUploader)).Methods("POST")

	redirectTpl, err := template.ParseFiles("static/redirect_notice.html")
	if err != nil {
		zap.L().Error("failed to parse the redirect notice HTML template", zap.Error(err))
		return
	}

	for _, sp := range cfg.ServiceProviders {
		zap.L().Debug("initializing service provider controller", zap.String("type", string(sp.ServiceProviderType)), zap.String("url", sp.ServiceProviderBaseUrl))

		controller, err := controllers.FromConfiguration(cfg, sp, authenticator, stateStorage, cl, strg, redirectTpl)
		if err != nil {
			zap.L().Error("failed to initialize controller: %s", zap.Error(err))
		}

		prefix := strings.ToLower(string(sp.ServiceProviderType))

		router.Handle(fmt.Sprintf("/%s/authenticate", prefix), http.HandlerFunc(controller.Authenticate)).Methods("GET", "POST")
		router.Handle(fmt.Sprintf("/%s/callback", prefix), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controller.Callback(r.Context(), w, r)
		})).Methods("GET")
	}

	zap.L().Info("Starting the server", zap.String("Addr", args.ServiceAddr))
	server := &http.Server{
		Addr: args.ServiceAddr,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      sessionManager.LoadAndSave(controllers.MiddlewareHandler(strings.Split(args.AllowedOrigins, ","), router)),
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := server.ListenAndServe(); err != nil {
			zap.L().Error("failed to start the HTTP server", zap.Error(err))
		}
	}()
	zap.L().Info("Server is up and running")
	// Setting up signal capturing
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Waiting for SIGINT (kill -2)
	<-stop
	zap.L().Info("Server got interrupt signal, going to gracefully shutdown the server", zap.Any("signal", stop))
	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	if err := server.Shutdown(ctx); err != nil {
		zap.L().Fatal("OAuth server shutdown failed", zap.Error(err))
	}
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	zap.L().Info("OAuth server exited properly")
	os.Exit(0)
}

func kubernetesConfig(args *cliArgs) (*rest.Config, error) {
	if args.KubeConfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", args.KubeConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create rest configuration: %w", err)
		}

		return cfg, nil
	} else if args.ApiServer != "" {
		// here we're essentially replicating what is done in rest.InClusterConfig() but we're using our own
		// configuration - this is to support going through an alternative API server to the one we're running with...
		// Note that we're NOT adding the Token or the TokenFile to the configuration here. This is supposed to be
		// handled on per-request basis...
		cfg := rest.Config{}

		apiServerUrl, err := url.Parse(args.ApiServer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the API server URL: %w", err)
		}

		cfg.Host = "https://" + net.JoinHostPort(apiServerUrl.Hostname(), apiServerUrl.Port())

		tlsConfig := rest.TLSClientConfig{}

		if args.ApiServerCAPath != "" {
			// rest.InClusterConfig is doing this most possibly only for early error handling so let's do the same
			if _, err := certutil.NewPool(args.ApiServerCAPath); err != nil {
				return nil, fmt.Errorf("expected to load root CA config from %s, but got err: %w", args.ApiServerCAPath, err)
			} else {
				tlsConfig.CAFile = args.ApiServerCAPath
			}
		}

		cfg.TLSClientConfig = tlsConfig

		return &cfg, nil
	} else {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize in-cluster config: %w", err)
		}
		return cfg, nil
	}
}
