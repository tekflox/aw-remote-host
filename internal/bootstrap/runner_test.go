package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// writeFakeModule creates <dir>/<name>/{install.sh,verify.sh} where
// verify.sh exits 0 only once markerFile exists, and install.sh creates
// markerFile — mimicking the real idempotent module contract without
// touching podman/apt.
func writeFakeModule(t *testing.T, dir, name string) (markerFile string) {
	t.Helper()
	modDir := filepath.Join(dir, name)
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	markerFile = filepath.Join(modDir, "installed.marker")
	verify := "#!/usr/bin/env bash\n[ -f \"" + markerFile + "\" ] && exit 0 || exit 1\n"
	install := "#!/usr/bin/env bash\ntouch \"" + markerFile + "\"\n"
	if err := os.WriteFile(filepath.Join(modDir, "verify.sh"), []byte(verify), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "install.sh"), []byte(install), 0o755); err != nil {
		t.Fatal(err)
	}
	return markerFile
}

func TestRunModuleInstallsWhenNotYetPresent(t *testing.T) {
	dir := t.TempDir()
	marker := writeFakeModule(t, dir, "widget")
	mod := Module{Name: "widget", VerifyCommand: "bootstrap/widget/verify.sh"}
	opts := RunOptions{ExtractDir: dir}

	status := RunModule(context.Background(), mod, opts)

	if status.AlreadyOK {
		t.Error("expected AlreadyOK=false on a fresh module")
	}
	if !status.Installed {
		t.Error("expected Installed=true")
	}
	if !status.OK {
		t.Errorf("expected OK=true after install, output:\n%s", status.Output)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("install.sh should have created the marker file: %v", err)
	}
}

func TestRunModuleSkipsInstallWhenAlreadyHealthy(t *testing.T) {
	dir := t.TempDir()
	marker := writeFakeModule(t, dir, "widget")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	mod := Module{Name: "widget", VerifyCommand: "bootstrap/widget/verify.sh"}
	opts := RunOptions{ExtractDir: dir}

	status := RunModule(context.Background(), mod, opts)

	if !status.AlreadyOK {
		t.Error("expected AlreadyOK=true when verify.sh already passes")
	}
	if status.Installed {
		t.Error("expected Installed=false — install.sh must not run when already healthy")
	}
	if !status.OK {
		t.Error("expected OK=true")
	}
}

func TestRunModuleReportsInstallFailure(t *testing.T) {
	dir := t.TempDir()
	modDir := filepath.Join(dir, "broken")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "verify.sh"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "install.sh"), []byte("#!/usr/bin/env bash\necho boom >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	mod := Module{Name: "broken", VerifyCommand: "bootstrap/broken/verify.sh"}
	opts := RunOptions{ExtractDir: dir}

	status := RunModule(context.Background(), mod, opts)

	if status.OK {
		t.Error("expected OK=false when install.sh fails")
	}
	if status.AlreadyOK {
		t.Error("expected AlreadyOK=false")
	}
}

func TestRunStopsAtFirstFailingModule(t *testing.T) {
	dir := t.TempDir()
	writeFakeModule(t, dir, "first")
	modDir := filepath.Join(dir, "second")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "verify.sh"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "install.sh"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A third module that would fail loudly if it ever ran, proving Run
	// stopped after "second" instead of continuing.
	third := filepath.Join(dir, "third")
	if err := os.MkdirAll(third, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(third, "ran.marker")
	if err := os.WriteFile(filepath.Join(third, "verify.sh"), []byte("#!/usr/bin/env bash\ntouch \""+sentinel+"\"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(third, "install.sh"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	m := &Manifest{Modules: []Module{
		{Name: "first", VerifyCommand: "bootstrap/first/verify.sh"},
		{Name: "second", VerifyCommand: "bootstrap/second/verify.sh"},
		{Name: "third", VerifyCommand: "bootstrap/third/verify.sh"},
	}}

	statuses, err := Run(context.Background(), m, RunOptions{ExtractDir: dir})
	if err == nil {
		t.Fatal("expected Run to return an error when a module fails")
	}
	if len(statuses) != 2 {
		t.Fatalf("expected exactly 2 statuses (stopped after the failing module), got %d", len(statuses))
	}
	if _, statErr := os.Stat(sentinel); !os.IsNotExist(statErr) {
		t.Error("third module's verify.sh ran even though the second module failed")
	}
}

func TestRunPassesExtraEnvToScripts(t *testing.T) {
	dir := t.TempDir()
	modDir := filepath.Join(dir, "envcheck")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "verify.sh"), []byte("#!/usr/bin/env bash\n[ \"$MY_VAR\" = \"hello\" ] && exit 0 || exit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "install.sh"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	mod := Module{Name: "envcheck", VerifyCommand: "bootstrap/envcheck/verify.sh"}
	opts := RunOptions{ExtractDir: dir, Env: []string{"MY_VAR=hello"}}

	ok, _ := Detect(context.Background(), mod, opts)
	if !ok {
		t.Error("expected Detect to see MY_VAR=hello and pass")
	}
}
