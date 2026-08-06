// Package certutil generates and manages the framework certificate
// authority (CA) used to sign per-host leaf certificates for HTTPS MITM.
// The private key never leaves the attacker's machine.
package certutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CA bundles the CA certificate and private key.
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey

	certPEM []byte
	keyPEM  []byte
	mu      sync.Mutex
	leaves  map[string]leaf
}

type leaf struct {
	certPEM []byte
	keyPEM  []byte
}

// GenerateCA creates a fresh CA and persists it to disk.
func GenerateCA(certPath, keyPath string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"toha3ee framework CA"}, CommonName: "toha3ee CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca := &CA{
		Cert:    cert,
		Key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		leaves:  make(map[string]leaf),
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		return nil, err
	}
	return ca, nil
}

// LoadOrCreateCA loads a CA from disk or generates a new one.
func LoadOrCreateCA(certPath, keyPath string) (*CA, error) {
	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		return ParseCA(certPEM, keyPEM)
	}
	return GenerateCA(certPath, keyPath)
}

// ParseCA decodes CA material from PEM bytes.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("invalid CA PEM material")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{
		Cert:    cert,
		Key:     key,
		certPEM: certPEM,
		keyPEM:  keyPEM,
		leaves:  make(map[string]leaf),
	}, nil
}

// Save writes the CA material to disk with restrictive permissions.
func (c *CA) Save(certPath, keyPath string) error {
	if err := os.WriteFile(certPath, c.certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, c.keyPEM, 0o600)
}

// TrustBundle returns the PEM certificate bytes, suitable for importing into
// a browser/OS trust store.
func (c *CA) TrustBundle() []byte {
	return c.certPEM
}

// LeafFor returns a cached per-host TLS certificate signed by the CA. Hosts
// matching an IP or DNS name are supported; a wildcard SAN is included so
// subdomains of the host also resolve.
func (c *CA) LeafFor(host string) ([]byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.leaves[host]; ok {
		return l.certPEM, l.keyPEM, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("leaf key: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
		if !isIP(host) {
			tmpl.DNSNames = append(tmpl.DNSNames, "*."+host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	c.leaves[host] = leaf{certPEM: certPEM, keyPEM: keyPEM}
	return certPEM, keyPEM, nil
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}
