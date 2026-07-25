// Package bootstrap loads the module manifest and orchestrates module
// install/verify. Real install/verify execution lands in card 4 — this
// skeleton wires the data model and the --plan dry-run path only.
package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
)

// Module describes one installable component from bootstrap/manifest.json.
type Module struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Image         string `json:"image,omitempty"`
	Digest        string `json:"digest,omitempty"`
	Package       string `json:"package,omitempty"`
	VerifyCommand string `json:"verify_command"`
}

// Manifest is the top-level bootstrap/manifest.json document.
type Manifest struct {
	Modules []Module `json:"modules"`
}

// LoadManifest reads and parses a manifest.json file from path.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
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
		return fmt.Sprintf("install package %s", mod.Package)
	}
	return fmt.Sprintf("install %s %s", mod.Name, mod.Version)
}

// Run executes install+verify for every module in the manifest. Stub for
// card 1 — real orchestration (idempotent detect/install/verify against the
// host) is implemented in card 4.
func Run(m *Manifest, plan bool) error {
	if plan {
		for _, a := range Plan(m) {
			fmt.Printf("[plan] %s: %s — %s\n", a.Module, a.Step, a.Detail)
		}
		return nil
	}
	return fmt.Errorf("bootstrap execution not implemented yet (see card 4); use --plan to preview")
}
