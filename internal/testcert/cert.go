package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"google.golang.org/grpc/credentials"
)

// Bundle contains a self-signed certificate and its encoded key pair.
type Bundle struct {
	Certificate tls.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

// Generate creates a self-signed certificate valid for localhost tests.
func Generate() (Bundle, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, fmt.Errorf("generate private key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Bundle{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("create certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return Bundle{}, fmt.Errorf("marshal private key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Bundle{}, fmt.Errorf("load certificate: %w", err)
	}
	return Bundle{Certificate: certificate, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// ServerCredentials returns TLS credentials for a generated certificate.
func (b Bundle) ServerCredentials() credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{b.Certificate}})
}

// ClientCredentials returns TLS credentials that trust the generated certificate.
func (b Bundle) ClientCredentials() (credentials.TransportCredentials, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b.CertPEM) {
		return nil, errors.New("append test certificate")
	}
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"}), nil
}
