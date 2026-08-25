// Package bootstrap loads the module manifest, extracts the embedded
// install/verify scripts to disk, and orchestrates idempotent
// detect->install->verify over each module. Real execution lives in
// runner.go; this file is the data model + --plan dry-run path.
package bootstrap

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	assets "github.com/tekflox/aw-remote-host/bootstrap"
)

// Module describes one installable component from bootstrap/manifest.json.
type Module struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Image   string `json:"image,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Package string `json:"package,omitempty"`
	// Source discloses where a package comes from when it is NOT the distro's
	// own repositories — the root README's transparency contract promises
	// "nothing is fetched from an undisclosed source", so a module that runs
	// an upstream installer has to name it here rather than only in a script.
	Source        string `json:"source,omitempty"`
	VerifyCommand string `json:"verify_command"`
	// Optional marks a module that a plain bootstrap must NOT run — it only
	// happens when something asks for it by name (Manifest.Only).
	//
	// Every module up to now was infrastructure the workspace cannot run
	// without, so "in the manifest" and "install it" meant the same thing.
	// The vpn module broke that: enrolling a machine in a network is a
	// decision its owner makes, not a side effect of provisioning a
	// workspace, and it needs inputs (a login server, a pre-auth key) that no
	// ordinary bootstrap has. Without this flag, adding it to the manifest
	// would make every --with-workspace run try to install tailscale and then
	// fail the whole bootstrap on the missing key.
	Optional bool `json:"optional,omitempty"`
}

// Manifest is the top-level bootstrap/manifest.json document.
type Manifest struct {
	Modules []Module `json:"modules"`
}

// LoadManifest reads and parses a manifest.json file from an arbitrary
// path — used by tests against the repo checkout.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return parseManifest(data)
}

// LoadEmbeddedManifest reads bootstrap/manifest.json embedded in the binary
// itself — what the compiled CLI actually uses at runtime, since
// install.sh only ships the binary, not a repo checkout (see the root
// README's transparency contract).
func LoadEmbeddedManifest() (*Manifest, error) {
	data, err := assets.FS.ReadFile("manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded manifest: %w", err)
	}
	return parseManifest(data)
}

func parseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// ExtractScripts writes every embedded module file (install.sh, verify.sh,
// README.md) to destDir, preserving the module subdirectory layout, and
// marks .sh files executable. Safe to call on every run — always
// overwrites, so a script fixed in a newer release replaces a stale copy
// left by an older one.
func ExtractScripts(destDir string) error {
	return fs.WalkDir(assets.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path == "manifest.json" {
			return nil
		}
		data, err := assets.FS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", path, err)
		}
		outPath := filepath.Join(destDir, path)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(outPath), err)
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(path, ".sh") {
			mode = 0o755
		}
		if err := os.WriteFile(outPath, data, mode); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		return nil
	})
}

// moduleScriptPath resolves a manifest verify_command (e.g.
// "bootstrap/redis/verify.sh", relative to the repo root) against the
// directory scripts were extracted to, and swaps in the sibling script
// name (verify.sh or install.sh) in that same module directory.
func moduleScriptPath(extractDir, verifyCommand, script string) string {
	rel := strings.TrimPrefix(verifyCommand, "bootstrap/")
	return filepath.Join(extractDir, filepath.Dir(rel), script)
}

// Action is a single planned or executed step against a module.
type Action struct {
	Module string
	Step   string // "detect", "install", "verify"
	Detail string
}

// Plan returns the ordered actions that Run would perform for each module,
// without executing anything — used by --plan mode.
func Plan(m *Manifest) []Action {
	actions := make([]Action, 0, len(m.Modules)*3)
	for _, mod := range m.Modules {
		actions = append(actions,
			Action{Module: mod.Name, Step: "detect", Detail: fmt.Sprintf("check if %s is already installed", mod.Name)},
			Action{Module: mod.Name, Step: "install", Detail: installDetail(mod)},
			Action{Module: mod.Name, Step: "verify", Detail: mod.VerifyCommand},
		)
	}
	return actions
}

func installDetail(mod Module) string {
	if mod.Digest != "" {
		return fmt.Sprintf("pull %s@%s", mod.Image, mod.Digest)
	}
	if mod.Package != "" {
		if mod.Source != "" {
			return fmt.Sprintf("install package %s from %s", mod.Package, mod.Source)
		}
		return fmt.Sprintf("install package %s", mod.Package)
	}
	return fmt.Sprintf("install %s %s", mod.Name, mod.Version)
}
