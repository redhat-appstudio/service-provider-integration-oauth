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
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/alexflint/go-arg"
	"github.com/gorilla/mux"
	"github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/logs"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/tokenstorage"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/redhat-appstudio/service-provider-integration-oauth/controllers"
)

func TestMain(m *testing.M) {
	logs.InitLoggers(true, flag.CommandLine)
	os.Exit(m.Run())
}

func TestHealthCheckHandler(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(OkHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestReadyCheckHandler(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/ready", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(OkHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestCallbackSuccessHandler(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/callback_success", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(CallbackSuccessHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestCallbackErrorHandler(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/github/callback?error=foo&error_description=bar", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(CallbackErrorHandler)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}
func TestUploader(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(v1beta1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&v1beta1.SPIAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "umbrella",
				Namespace: "jdoe",
			},
		},
	).Build()

	strg := tokenstorage.NotifyingTokenStorage{
		Client: cl,
		TokenStorage: tokenstorage.TestTokenStorage{
			StoreImpl: func(ctx context.Context, token *v1beta1.SPIAccessToken, data *v1beta1.Token) error {
				assert.Equal(t, v1beta1.Token{
					AccessToken: "42",
				}, *data)
				return nil
			},
		},
	}

	uploader := &controllers.TokenUploader{
		K8sClient: cl,
		Storage:   strg,
	}

	req, err := http.NewRequest("POST", "/token/jdoe/umbrella", bytes.NewBuffer([]byte(`{"access_token": "42"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer kachny")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	var router = mux.NewRouter()
	router.NewRoute().Path("/token/{namespace}/{name}").HandlerFunc(handleUpload(uploader)).Methods("POST")

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	router.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusAccepted)
	}
}

func TestUploader_FailWithEmptyToken(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(v1beta1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&v1beta1.SPIAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "umbrella",
				Namespace: "jdoe",
			},
		},
	).Build()

	strg := tokenstorage.NotifyingTokenStorage{
		Client: cl,
		TokenStorage: tokenstorage.TestTokenStorage{
			StoreImpl: func(ctx context.Context, token *v1beta1.SPIAccessToken, data *v1beta1.Token) error {
				assert.Fail(t, "should fail earlier")
				return nil
			},
		},
	}

	uploader := &controllers.TokenUploader{
		K8sClient: cl,
		Storage:   strg,
	}

	req, err := http.NewRequest("POST", "/token/jdoe/umbrella", bytes.NewBuffer([]byte(`{"username": "jdoe"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer kachny")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	w := httptest.NewRecorder()
	var router = mux.NewRouter()
	router.NewRoute().Path("/token/{namespace}/{name}").HandlerFunc(handleUpload(uploader)).Methods("POST")

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	router.ServeHTTP(w, req)
	res := w.Result()
	defer res.Body.Close()
	// Check the status code is what we expect.

	if status := res.StatusCode; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "access token can't be omitted or empty" {
		t.Errorf("expected 'access token can't be omitted or empty' got '%v'", string(data))
	}
}

func TestK8sConfigParse(t *testing.T) {
	//given
	cmd := ""
	env := []string{"API_SERVER=http://localhost:9001", "API_SERVER_CA_PATH=/etc/ca.crt"}
	//then
	args := cliArgs{}
	_, err := parseWithEnv(cmd, env, &args)
	//when
	if err != nil {
		t.Fatal(err)
	}
	if args.ApiServer != "http://localhost:9001" {
		t.Fatal("Unable to parse k8s api server url")
	}
	if args.ApiServerCAPath != "/etc/ca.crt" {
		t.Fatal("Unable to parse k8s ca path")
	}
}

func TestCorsConfigParse(t *testing.T) {
	//given
	cmd := ""
	env := []string{"ALLOWEDORIGINS=prod.acme.com"}
	//then
	args := cliArgs{}
	_, err := parseWithEnv(cmd, env, &args)
	//when
	if err != nil {
		t.Fatal(err)
	}
	if args.AllowedOrigins != "prod.acme.com" {
		t.Fatal("Unable to parse CORS allowed origins")
	}
}

func parseWithEnv(cmdline string, env []string, dest interface{}) (*arg.Parser, error) {
	p, err := arg.NewParser(arg.Config{}, dest)
	if err != nil {
		return nil, err
	}

	// split the command line
	var parts []string
	if len(cmdline) > 0 {
		parts = strings.Split(cmdline, " ")
	}

	// split the environment vars
	for _, s := range env {
		pos := strings.Index(s, "=")
		if pos == -1 {
			return nil, fmt.Errorf("missing equals sign in %q", s)
		}
		err := os.Setenv(s[:pos], s[pos+1:])
		if err != nil {
			return nil, err
		}
	}

	// execute the parser
	return p, p.Parse(parts)
}

func TestMiddlewareHandlerCorsPart(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/github/callback?error=foo&error_description=bar", nil)
	req.Header.Set("Origin", "https://prod.foo.redhat.com")
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := MiddlewareHandler([]string{"https://console.dev.redhat.com", "https://prod.foo.redhat.com"}, http.HandlerFunc(OkHandler))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the status code is what we expect.
	if allowOrigin := rr.Header().Get("Access-Control-Allow-Origin"); allowOrigin != "https://prod.foo.redhat.com" {
		t.Errorf("handler returned wrong header \"Access-Control-Allow-Origin\": got %v want %v",
			allowOrigin, "prod.foo.redhat.com")
	}

}

func TestMiddlewareHandlerCorsPart2(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("OPTIONS", "/github/authenticate?state=eyJhbGciO", nil)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "c")
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Origin", "https://file-retriever-server-service-spi-system.apps.cluster-flmv6.flmv6.sandbox1324.opentlc.com")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", "https://file-retriever-server-service-spi-system.apps.cluster-flmv6.flmv6.sandbox1324.opentlc.com/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36")
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := MiddlewareHandler([]string{"https://file-retriever-server-service-spi-system.apps.cluster-flmv6.flmv6.sandbox1324.opentlc.com", "http:://acme.com"}, http.HandlerFunc(OkHandler))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the status code is what we expect.
	if allowOrigin := rr.Header().Get("Access-Control-Allow-Origin"); allowOrigin != "https://file-retriever-server-service-spi-system.apps.cluster-flmv6.flmv6.sandbox1324.opentlc.com" {
		t.Errorf("handler returned wrong header \"Access-Control-Allow-Origin\": got %v want %v",
			allowOrigin, "https://file-retriever-server-service-spi-system.apps.cluster-flmv6.flmv6.sandbox1324.opentlc.com")
	}

}
