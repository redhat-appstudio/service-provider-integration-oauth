/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"net/http"
	"os"
	"spi-oauth/config"
	"spi-oauth/controllers"
	"spi-oauth/log"
)

type cliArgs struct {
	ConfigFile string `arg:"-c, --config-file, env" default:"/etc/spi/config.yaml" help:"The location of the configuration file"`
	Port       int    `arg:"-p, --port, env" default:"8000" help:"The port to listen on"`
	DevMode    bool   `arg:"-d, --dev-mode, env" default:"false" help:"use dev-mode logging"`
}

func main() {
	args := cliArgs{}
	arg.MustParse(&args)

	// must be done prior to any usage of log
	log.DevMode = args.DevMode

	cfg, err := config.LoadFrom(args.ConfigFile)
	if err != nil {
		log.Error("failed to load configuration", zap.Error(err))
		os.Exit(1)
	}

	start(cfg, args.Port)
}

func start(cfg config.Configuration, port int) {
	router := mux.NewRouter()

	for _, sp := range cfg.ServiceProviders {
		controller, err := controllers.FromConfiguration(sp)
		if err != nil {
			log.Error("failed to initialize controller: %s", zap.Error(err))
		}
		router.Handle(fmt.Sprintf("/%s/authenticate", sp), http.HandlerFunc(controller.Authenticate)).Methods("GET")
		router.Handle(fmt.Sprintf("/%s/callback", sp), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controller.Callback(context.Background(), w, r)
		})).Methods("GET")
	}

	err := http.ListenAndServe(fmt.Sprintf(":%d", port), router)
	if err != nil {
		log.Error("failed to start the HTTP server", zap.Error(err))
	}
}
