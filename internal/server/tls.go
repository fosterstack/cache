package server

import "crypto/tls"

// TLSConfig is the server's TLS configuration for one certificate
// (REQ-TLS-001). MinVersion is TLS 1.2, set explicitly so no runtime
// setting can lower it; CipherSuites stays nil, which is Go's default list
// (TLS 1.3 suites are not configurable in Go). In the -fips build Go's
// FIPS 140-3 mode narrows versions, suites, curves and signature
// algorithms further by itself.
//
// NextProtos offers only http/1.1 by ALPN (REQ-TLS-001-AC9): HTTP/2 is not
// offered, so a client offering only h2 fails ALPN negotiation. Together
// with the HTTP/1-only Protocols set in NewHTTPServer, ServeTLS does not
// add h2 back.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
}
