// Package lanfastpath is the host side of the LAN fast-path (case a): when a
// browser runs on (or on the same LAN as) the workspace machine, it reaches
// aw-workspace directly at the machine's LAN IP instead of routing
// api.<slug>.workspace.aw.tekflox.com through internet -> cloud edge -> /link
// tunnel -> back.
//
// The crux (see docs/architecture/aw-workspace-lan-fastpath.md): a browser on
// the HTTPS cloud SPA cannot fetch http://<lan-ip> (mixed content) and no
// public cert exists for a raw IP. So the local path reuses a real HTTPS
// hostname — local.<slug>.workspace.aw.tekflox.com, covered by the per-
// workspace wildcard cert *.<slug>.workspace.aw.tekflox.com — published in
// public DNS as an A record pointing at the LAN IP. This host terminates TLS
// locally on a high port (8443, no root needed) with that same cert and
// reverse-proxies to the local plaintext aw-workspace (127.0.0.1:9030, the
// same target internal/tunnelproxy forwards to).
//
// Off-LAN the public A record still resolves to the LAN IP, which is
// unreachable, so the SPA's probe fails fast and falls back to the tunnel
// path (api.<slug>.workspace...). Identity is validated identically on the
// local path — aw-workspace enforces aw_id_jwt regardless of which listener
// served the request — so this never exposes the API unauthenticated.
package lanfastpath

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// DefaultPort is the high (non-privileged) TLS port the terminator binds.
// Kept out of the 1-1023 range so it needs no root — macbook-fred's `aw`
// user has no passwordless sudo (the whole reason case (a) uses 8443, not
// 443). Override with AW_LAN_FASTPATH_PORT.
const DefaultPort = 8443

// DefaultTarget is the local plaintext aw-workspace this host bootstrapped —
// the same address internal/tunnelproxy.DefaultTarget forwards to.
const DefaultTarget = "http://127.0.0.1:9030"

// Config parameterises the terminator.
type Config struct {
	Port     int    // TLS listen port; DefaultPort if zero
	CertFile string // PEM cert (wildcard *.<slug>.workspace.aw.tekflox.com)
	KeyFile  string // PEM private key
	Target   string // upstream base URL; DefaultTarget if empty
}

func (c Config) port() int {
	if c.Port > 0 {
		return c.Port
	}
	return DefaultPort
}

func (c Config) target() string {
	if c.Target != "" {
		return c.Target
	}
	return DefaultTarget
}

// TLSDir returns ~/.aw-remote-host/tls — where the control plane drops (and
// this host reads) the per-workspace cert + key delivered over /link.
func TLSDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".aw-remote-host", "tls"), nil
}

// LocateCert returns the cert/key paths for a workspace slug under TLSDir,
// and whether both exist. The naming matches what the control-plane delivery
// stages: tls/api.<slug>.workspace.crt / .key (the wildcard cert also covers
// local.<slug>.workspace..., so one file serves every subdomain).
func LocateCert(slug string) (certFile, keyFile string, ok bool) {
	dir, err := TLSDir()
	if err != nil {
		return "", "", false
	}
	certFile = filepath.Join(dir, "api."+slug+".workspace.crt")
	keyFile = filepath.Join(dir, "api."+slug+".workspace.key")
	if !fileExists(certFile) || !fileExists(keyFile) {
		return certFile, keyFile, false
	}
	return certFile, keyFile, true
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// LANAddrs enumerates this host's non-loopback IPv4 addresses that are in
// RFC-1918 private ranges (the LAN IPs worth advertising to the control
// plane for the public A record). Ordered as the OS returns interfaces;
// callers that need "the primary" should prefer the first that matches the
// default route, but the full list is advertised so the SPA can probe any.
func LANAddrs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := addrIP(a)
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 == nil || !ip.IsPrivate() {
				continue
			}
			out = append(out, v4.String())
		}
	}
	return out
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// Serve runs the TLS terminator until ctx is cancelled (graceful shutdown)
// or the listener fails. It reverse-proxies every request to the local
// plaintext aw-workspace, preserving the original Host header so the
// upstream sees the same hostname the tunnel path would present.
func Serve(ctx context.Context, cfg Config) error {
	upstream, err := url.Parse(cfg.target())
	if err != nil {
		return fmt.Errorf("parse upstream %q: %w", cfg.target(), err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// Preserve the client's Host header (local.<slug>.workspace...) rather
	// than rewriting it to the upstream's 127.0.0.1 — aw-workspace's CORS /
	// cookie / identity logic keys off the original host, same as the tunnel.
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		host := r.Host
		origDirector(r)
		r.Host = host
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.port()),
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
