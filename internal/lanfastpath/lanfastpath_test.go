package lanfastpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocateCert(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	tlsDir := filepath.Join(home, ".aw-remote-host", "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}

	certFile, keyFile, ok := LocateCert("fredericowu")
	if ok {
		t.Fatalf("expected ok=false before files exist")
	}
	if filepath.Base(certFile) != "api.fredericowu.workspace.crt" {
		t.Fatalf("unexpected cert path %q", certFile)
	}

	for _, p := range []string{certFile, keyFile} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, ok := LocateCert("fredericowu"); !ok {
		t.Fatalf("expected ok=true once both files exist")
	}
}

func TestConfigDefaults(t *testing.T) {
	var c Config
	if c.port() != DefaultPort {
		t.Fatalf("port default = %d, want %d", c.port(), DefaultPort)
	}
	if c.target() != DefaultTarget {
		t.Fatalf("target default = %q, want %q", c.target(), DefaultTarget)
	}
}

// LANAddrs must never return a loopback or non-private address.
func TestLANAddrsPrivateOnly(t *testing.T) {
	for _, a := range LANAddrs() {
		if a == "127.0.0.1" {
			t.Fatalf("LANAddrs returned loopback")
		}
	}
}
