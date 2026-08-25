package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

// ModuleStatus is the detect->install->verify outcome for one module.
type ModuleStatus struct {
	Module    string
	AlreadyOK bool   // verify.sh succeeded before install.sh ever ran
	Installed bool   // install.sh ran (AlreadyOK was false)
	OK        bool   // verify.sh succeeded after detect/install
	Output    string // combined script output, for diagnostics/reporting
}

// RunOptions configures a real (non---plan) bootstrap pass.
type RunOptions struct {
	ExtractDir string   // dir scripts were extracted to (see ExtractScripts)
	Env        []string // extra "KEY=value" env vars appended for every script
	Stdout     io.Writer
	Stderr     io.Writer
}

func (o RunOptions) stdout() io.Writer {
	if o.Stdout != nil {
		return o.Stdout
	}
	return os.Stdout
}

func (o RunOptions) stderr() io.Writer {
	if o.Stderr != nil {
		return o.Stderr
	}
	return os.Stderr
}

func runScript(ctx context.Context, path string, opts RunOptions) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("script not found: %s: %w", path, err)
	}
	cmd := exec.CommandContext(ctx, "bash", path)
	env := append(os.Environ(), opts.Env...)
	if dir, ok := podmanVendoredBinDir(); ok {
		// exec.Cmd keeps only the last value for a duplicate env key, so
		// appending PATH last here overrides the inherited os.Environ()
		// one — this is how a vendored podman (bootstrap/podman/install.sh's
		// brew-less macOS path) becomes visible to every module that runs
		// after it (postgres/redis/workspace call `podman` directly), across
		// both the same Run() call and separate ones (e.g. cmd/aw-remote-
		// host/commands.go runs infra and workspace as two Run() calls).
		// A no-op when podman is already on PATH normally.
		env = append(env, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout = io.MultiWriter(&buf, opts.stdout())
	cmd.Stderr = io.MultiWriter(&buf, opts.stderr())
	err := cmd.Run()
	return buf.String(), err
}

// podmanVendoredBinDir reports the vendored podman bin directory written by
// bootstrap/podman/install.sh's install_vendored_podman() (macOS, no brew),
// if it exists on this machine — the runner's half of the dependency
// propagation contract documented in bootstrap/lib/README.md.
func podmanVendoredBinDir() (string, bool) {
	home, err := homedir.Dir()
	if err != nil {
		return "", false
	}
	dir := filepath.Join(home, "podman-dist", "podman", "bin")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return dir, true
}

// Detect runs a module's verify.sh and reports whether it's already
// healthy — the idempotency check every module goes through before its
// install.sh is ever invoked.
func Detect(ctx context.Context, mod Module, opts RunOptions) (bool, string) {
	path := moduleScriptPath(opts.ExtractDir, mod.VerifyCommand, "verify.sh")
	out, err := runScript(ctx, path, opts)
	return err == nil, out
}

// Install runs a module's install.sh.
func Install(ctx context.Context, mod Module, opts RunOptions) (string, error) {
	path := moduleScriptPath(opts.ExtractDir, mod.VerifyCommand, "install.sh")
	return runScript(ctx, path, opts)
}

// Verify runs a module's verify.sh.
func Verify(ctx context.Context, mod Module, opts RunOptions) (string, error) {
	path := moduleScriptPath(opts.ExtractDir, mod.VerifyCommand, "verify.sh")
	return runScript(ctx, path, opts)
}

// RunModule performs the full idempotent detect->install->verify cycle for
// one module: if Detect already reports healthy, install.sh is skipped
// entirely; otherwise install.sh runs and verify.sh confirms it worked.
func RunModule(ctx context.Context, mod Module, opts RunOptions) ModuleStatus {
	status := ModuleStatus{Module: mod.Name}

	ok, out := Detect(ctx, mod, opts)
	status.Output = out
	if ok {
		status.AlreadyOK = true
		status.OK = true
		return status
	}

	status.Installed = true
	installOut, err := Install(ctx, mod, opts)
	status.Output += installOut
	if err != nil {
		status.Output += fmt.Sprintf("\ninstall failed: %v", err)
		return status
	}

	verifyOut, err := Verify(ctx, mod, opts)
	status.Output += verifyOut
	status.OK = err == nil
	if err != nil {
		status.Output += fmt.Sprintf("\nverify failed after install: %v", err)
	}
	return status
}

// Run performs detect->install->verify for every module in the manifest,
// in manifest order, stopping at the first module that doesn't come up
// healthy — later modules generally depend on earlier ones (podman before
// postgres/redis/workspace).
func Run(ctx context.Context, m *Manifest, opts RunOptions) ([]ModuleStatus, error) {
	statuses := make([]ModuleStatus, 0, len(m.Modules))
	for _, mod := range m.Modules {
		st := RunModule(ctx, mod, opts)
		statuses = append(statuses, st)
		if !st.OK {
			return statuses, fmt.Errorf("module %q failed:\n%s", mod.Name, st.Output)
		}
	}
	return statuses, nil
}

// Except returns a Manifest with the named modules dropped — used to run
// the infra modules (podman/postgres/redis) before the workspace module,
// which needs the workspace slug from the /link registration reply.
func (m *Manifest) Except(names ...string) *Manifest {
	skip := make(map[string]bool, len(names))
	for _, n := range names {
		skip[n] = true
	}
	out := &Manifest{}
	for _, mod := range m.Modules {
		if !skip[mod.Name] {
			out.Modules = append(out.Modules, mod)
		}
	}
	return out
}

// Default returns the modules a plain bootstrap runs — everything that is
// not opt-in. Callers that mean "all the modules this host is supposed to
// have" want this, not the raw manifest; see Module.Optional.
func (m *Manifest) Default() *Manifest {
	out := &Manifest{}
	for _, mod := range m.Modules {
		if !mod.Optional {
			out.Modules = append(out.Modules, mod)
		}
	}
	return out
}

// Only returns a Manifest containing just the named modules, in manifest
// order. It ignores Optional on purpose — naming a module IS the opt-in.
func (m *Manifest) Only(names ...string) *Manifest {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := &Manifest{}
	for _, mod := range m.Modules {
		if want[mod.Name] {
			out.Modules = append(out.Modules, mod)
		}
	}
	return out
}
