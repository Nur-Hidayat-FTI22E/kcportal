// Package pki implements the local-CA (T1) certificate plane for the
// PoS App Pack (DD-09): kcportald's world stays offline, so there is
// no ACME — a venue-private CA signs the apps-proxy certificate and
// cashiers' browsers install the CA once via pos-onboard (T2/public
// arrives in M6).
//
// Everything is idempotent and crash-safe: EnsureCA creates the CA
// exactly once (later calls load and verify it), EnsureServerCert
// (re)issues only when the certificate is missing, expired-soon, or
// no longer matches the requested hosts. Files: ca.crt/ca.key/
// server.crt/server.key inside dir; keys 0600, certs 0644.
package pki

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
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"

	caOrg          = "kotacloud local CA"
	leafOrg        = "kotacloud pos"
	leafMaxDays    = 825 // iOS caps manually-trusted leaf validity
	renewBefore    = 30 * 24 * time.Hour
	bigEndian1e128 = 128
)

// CA bundles the parsed authority used to sign leaves.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	DER  []byte // ca.crt bytes (PEM)
}

// EnsureCA loads the CA from dir, creating it on first call. A CA that
// fails to parse, fails to match its key, or is already expired is an
// error — the operator must delete the directory to re-key deliberately
// (a silently rotated CA would strand every installed browser).
func EnsureCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := loadCA(certPEM, keyPEM)
		if err == nil {
			return ca, nil
		}
		return nil, fmt.Errorf("pki: existing CA unusable in %s (delete to re-key deliberately): %w", dir, err)
	}
	if !(os.IsNotExist(certErr) && os.IsNotExist(keyErr)) && certErr != nil && keyErr != nil {
		return nil, fmt.Errorf("pki: read CA: %w", errors.Join(certErr, keyErr))
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{caOrg}, CommonName: "kotacloud root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = marshalKey(key)
	if err := writeFiles(dir, map[string][]byte{caCertFile: certPEM, caKeyFile: keyPEM}); err != nil {
		return nil, err
	}
	return loadCA(certPEM, keyPEM)
}

// EnsureServerCert returns the leaf key pair for hosts (DNS names
// and/or IP literals), issuing it from ca when missing, mismatched, or
// within renewBefore of expiry. The pair is validated (cert matches
// key) before any reuse.
func (ca *CA) EnsureServerCert(dir string, hosts []string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, serverCertFile)
	keyPath := filepath.Join(dir, serverKeyFile)
	if certPEM, cerr := os.ReadFile(certPath); cerr == nil {
		if keyPEM, kerr := os.ReadFile(keyPath); kerr == nil {
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err == nil && certCovers(&pair, hosts) && time.Until(pair.Leaf.NotAfter) > renewBefore {
				return pair, nil
			}
			// fall through: regenerate
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{leafOrg}, CommonName: hosts[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, leafMaxDays),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// The served chain: leaf + CA (browsers without the CA installed
	// see the full chain; with it installed, the extra cert is harmlessly
	// ignored).
	certPEM = append(certPEM, ca.DER...)
	keyPEM := marshalKey(key)
	if err := writeFiles(dir, map[string][]byte{serverCertFile: certPEM, serverKeyFile: keyPEM}); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// CaCertPEM returns the CA certificate bytes for the onboard download.
func (ca *CA) CaCertPEM() []byte { return ca.DER }

func loadCA(certPEM, keyPEM []byte) (*CA, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, err
		}
	}
	if !leaf.IsCA {
		return nil, errors.New("pki: ca.crt is not a CA certificate")
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("pki: CA expired %s", leaf.NotAfter.Format(time.RFC3339))
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pki: CA key is %T, want ECDSA", pair.PrivateKey)
	}
	return &CA{Cert: leaf, Key: key, DER: certPEM}, nil
}

func certCovers(pair *tls.Certificate, hosts []string) bool {
	if pair.Leaf == nil {
		return false
	}
	for _, h := range hosts {
		if err := pair.Leaf.VerifyHostname(h); err != nil {
			return false
		}
	}
	return true
}

func marshalKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic("pki: marshal EC key: " + err.Error()) // cannot happen for our own keys
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func writeFiles(dir string, files map[string][]byte) error {
	for name, data := range files {
		mode := os.FileMode(0o644)
		if filepath.Ext(name) == ".key" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			return err
		}
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), bigEndian1e128)
	return rand.Int(rand.Reader, limit)
}
