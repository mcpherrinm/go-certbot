package client

import (
	"crypto/tls"
	"net/http"
)

// insecureTransport returns a transport that skips TLS verification. Used when
// --no-verify-ssl is set, primarily for talking to Pebble in tests.
func insecureTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // user opt-in
}
