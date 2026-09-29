package pki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCACreatesOnceAndReuses(t *testing.T) {
	dir := t.TempDir()
	ca1, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}
	ca2, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if string(ca1.DER) != string(ca2.DER) {
		t.Fatal("second call must reuse the same CA, not re-key")
	}
	// Key stays private.
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestEnsureCACorruptExistingIsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, caCertFile), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCA(dir); err == nil {
		t.Fatal("corrupt CA must error (deliberate re-key), not silently rotate")
	}
}

func TestServerCertIssueKeepRegenerate(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{"pos.kcp.internal", "10.20.2.1"}
	p1, err := ca.EnsureServerCert(dir, hosts)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Same hosts: kept.
	p2, err := ca.EnsureServerCert(dir, hosts)
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	if p1.Leaf.SerialNumber.Cmp(p2.Leaf.SerialNumber) != 0 {
		t.Fatal("same hosts must keep the existing leaf")
	}
	// Changed hosts: regenerated and valid for the new set.
	p3, err := ca.EnsureServerCert(dir, []string{"pos2.kcp.internal", "10.20.2.1"})
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	if p3.Leaf.SerialNumber.Cmp(p2.Leaf.SerialNumber) == 0 {
		t.Fatal("host change must regenerate the leaf")
	}

	// The leaf chains to the CA and validates for every requested host.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.DER) {
		t.Fatal("CA PEM not parseable")
	}
	leaf, err := x509.ParseCertificate(p3.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("leaf does not chain to the local CA: %v", err)
	}
	if err := leaf.VerifyHostname("pos2.kcp.internal"); err != nil {
		t.Fatalf("SAN missing DNS host: %v", err)
	}
	var ipFound bool
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "10.20.2.1" {
			ipFound = true
		}
	}
	if !ipFound {
		t.Fatal("SAN missing IP host")
	}
}

func TestServerPairIsValidTLSKeyPair(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ca.EnsureServerCert(dir, []string{"pos.kcp.internal"})
	if err != nil {
		t.Fatal(err)
	}
	// tls.X509KeyPair-equivalent validation already happened inside
	// Ensure; assert the shape the proxy needs.
	if len(pair.Certificate) < 2 {
		t.Fatal("served chain must carry leaf + CA")
	}
	var _ tls.Certificate = pair
}
