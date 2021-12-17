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
	"net/http"
	"os"
	"strings"

	"github.com/alexflint/go-arg"

	"github.com/redhat-appstudio/service-provider-integration-oauth/controllers"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/config"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type cliArgs struct {
	ConfigFile string `arg:"-c, --config-file, env" default:"/etc/spi/config.yaml" help:"The location of the configuration file"`
	Port       int    `arg:"-p, --port, env" default:"8000" help:"The port to listen on"`
	DevMode    bool   `arg:"-d, --dev-mode, env" default:"false" help:"use dev-mode logging"`
}

func OkHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func main() {
	args := cliArgs{}
	arg.MustParse(&args)

	var logger *zap.Logger
	if args.DevMode {
		logger, _ = zap.NewDevelopment()
	} else {
		logger, _ = zap.NewProduction()
	}
	if logger != nil {
		zap.ReplaceGlobals(logger)
	}

	pcfg, err := config.LoadFrom(args.ConfigFile)
	if err != nil {
		zap.L().Error("failed to load configuration", zap.Error(err))
		os.Exit(1)
	}

	cfg, err := pcfg.Inflate()
	if err != nil {
		zap.L().Error("failed to initialize the configuration", zap.Error(err))
		os.Exit(1)
	}

	start(cfg, args.Port)
}

func start(cfg config.Configuration, port int) {
	router := mux.NewRouter()

	for _, sp := range cfg.ServiceProviders {
		controller, err := controllers.FromConfiguration(cfg, sp)
		if err != nil {
			zap.L().Error("failed to initialize controller: %s", zap.Error(err))
		}

		prefix := strings.ToLower(string(sp.ServiceProviderType))

		router.Handle(fmt.Sprintf("/%s/authenticate", prefix), http.HandlerFunc(controller.Authenticate)).Methods("GET")
		router.Handle(fmt.Sprintf("/%s/callback", prefix), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controller.Callback(context.Background(), w, r)
		})).Methods("GET")
	}
	router.HandleFunc("/health", OkHandler).Methods("GET")
	router.HandleFunc("/ready", OkHandler).Methods("GET")

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), router)
	if err != nil {
		zap.L().Error("failed to start the HTTP server", zap.Error(err))
	}
}
