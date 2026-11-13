package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type upstream struct {
	origin string
	client *http.Client
	token  string
}

// Resolve once per session. Dial only that address, authenticate the configured
// TLS name/certificate, never use host proxy settings and never follow redirects.
func prepareUpstream(ctx context.Context, e Endpoint) (*upstream, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	u, _ := url.Parse(e.URL)
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, u.Hostname())
	if err != nil || len(ips) == 0 || len(ips) > 16 {
		return nil, errors.New("broker endpoint address could not be bound")
	}
	for _, a := range ips {
		if a.Zone != "" || a.IP.IsUnspecified() || a.IP.IsMulticast() || a.IP.IsLinkLocalUnicast() || a.IP.IsLinkLocalMulticast() {
			return nil, errors.New("broker endpoint resolved to a prohibited address class")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(ips[0].IP.String(), port)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if e.CertificateSHA256 != "" {
		pin, _ := hex.DecodeString(e.CertificateSHA256)
		tlsConfig.InsecureSkipVerify = true // Replaced by exact certificate/name/time verification below.
		tlsConfig.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return errors.New("broker server certificate missing")
			}
			cert := s.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) || cert.VerifyHostname(u.Hostname()) != nil {
				return errors.New("broker server identity mismatch")
			}
			return nil
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true, MaxIdleConns: 4, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 15 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16 * 1024,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}).DialContext(ctx, network, address)
		},
	}
	token := ""
	if e.CredentialEnv != "" {
		var ok bool
		token, ok = os.LookupEnv(e.CredentialEnv)
		if !ok || len(token) < 1 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
			return nil, errors.New("explicit broker host credential is missing or invalid")
		}
	}
	return &upstream{origin: strings.TrimSuffix(e.URL, "/"), token: token, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (u *upstream) close() { u.client.CloseIdleConnections() }
