package server

import "crypto/tls"

// TLSConfig is the server's TLS configuration for one certificate
// (REQ-TLS-001). MinVersion is TLS 1.2, set explicitly so no runtime
// setting can lower it; CipherSuites stays nil, which is Go's default list
// (TLS 1.3 suites are not configurable in Go). In the -fips build Go's
// FIPS 140-3 mode narrows versions, suites, curves and signature
// algorithms further by itself.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
}
