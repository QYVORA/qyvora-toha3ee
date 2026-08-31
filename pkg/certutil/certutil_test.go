package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateAndLoadCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := GenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Fatal("certificate is not a CA")
	}

	// Key file must be 0600.
	info, _ := os.Stat(keyPath)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %v", info.Mode().Perm())
	}

	loaded, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if !loaded.Cert.Equal(ca.Cert) {
		t.Fatal("loaded CA cert differs")
	}
}

func TestLoadOrCreateGeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(dir, "a.pem"), filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if ca.Cert == nil {
		t.Fatal("no CA generated")
	}
}

func TestLeafForDNSAndIP(t *testing.T) {
	ca, _ := GenerateCA(filepath.Join(t.TempDir(), "c.pem"), filepath.Join(t.TempDir(), "c.key"))

	for _, host := range []string{"www.bank.com", "192.168.8.116"} {
		certPEM, keyPEM, err := ca.LeafFor(host)
		if err != nil {
			t.Fatalf("LeafFor(%s): %v", host, err)
		}
		cb, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			t.Fatalf("leaf does not verify against CA: %v", err)
		}
		if kb, _ := pem.Decode(keyPEM); kb == nil {
			t.Fatal("no leaf private key")
		}
	}
}

func TestLeafCacheReturnsSame(t *testing.T) {
	ca, _ := GenerateCA(filepath.Join(t.TempDir(), "c.pem"), filepath.Join(t.TempDir(), "c.key"))
	c1, _, _ := ca.LeafFor("bank.com")
	c2, _, _ := ca.LeafFor("bank.com")
	if string(c1) != string(c2) {
		t.Fatal("leaf cache did not return identical certs")
	}
}

func TestLeafWildcardSAN(t *testing.T) {
	ca, _ := GenerateCA(filepath.Join(t.TempDir(), "c.pem"), filepath.Join(t.TempDir(), "c.key"))
	certPEM, _, err := ca.LeafFor("bank.com")
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(cb.Bytes)
	found := false
	for _, name := range cert.DNSNames {
		if name == "*.bank.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no wildcard SAN: %v", cert.DNSNames)
	}
}

func TestTrustBundle(t *testing.T) {
	ca, _ := GenerateCA(filepath.Join(t.TempDir(), "c.pem"), filepath.Join(t.TempDir(), "c.key"))
	bundle := ca.TrustBundle()
	if len(bundle) == 0 {
		t.Fatal("empty trust bundle")
	}
	if _, err := net.ParseMAC(""); err != nil {
		_ = err
	}
}
