// +build !release

package controllers

import "net/http"

type fakeRoundTrip func(r *http.Request) (*http.Response, error)

func (f fakeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
