package wsl

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Report is what the caller prints as provisioning proceeds. Each step is
// announced before it runs, because the slow ones (kernel update, a 325 MB
// rootfs download, the workspace image pull) are long enough that silence
// reads as a hang.
type Report func(format string, args ...any)

// Options configures ProvisionWorkspace.
type Options struct {
	Distro       string // defaults to DefaultDistro
	Token        string // bootstrap token, required on a distro that has never linked
	ControlPlane string
	RootDir      string // where the distro and the cached rootfs live
	Log          Report
}

func (o *Options) applyDefaults() {
	if o.Distro == "" {
		o.Distro = DefaultDistro
	}
	if o.RootDir == "" {
		// Under the user's profile, not Program Files: this install needs no
		// admin rights anywhere else and should not start needing them here.
		if home, err := os.UserHomeDir(); err == nil {
			o.RootDir = filepath.Join(home, ".aw-remote-host", "wsl")
		} else {
			o.RootDir = filepath.Join(os.TempDir(), "aw-remote-host-wsl")
		}
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
}

// ProvisionWorkspace stands up a WSL2 distro that hosts the workspace, and
// arranges for it to come back at logon.
//
// Idempotent throughout: an existing distro is reused rather than
// re-imported (re-importing would silently discard the workspace's postgres
// volume), a cached rootfs is not re-downloaded, and the inner
// bootstrap-workspace is itself a detect→install→verify cycle.
func ProvisionWorkspace(opts Options) error {
	opts.applyDefaults()

	if err := Available(); err != nil {
		return err
	}

	exists, err := DistroExists(opts.Distro)
	if err != nil {
		return fmt.Errorf("list wsl distros: %w", err)
	}

	if !exists {
		opts.Log("wsl: updating the WSL kernel (this can take a minute)")
		if out, err := UpdateKernel(); err != nil {
			// Not fatal. A machine with a current kernel reports "no updates
			// available" as a non-zero exit on some builds, and refusing to
			// continue over that would block a host that is already fine.
			opts.Log("wsl: kernel update reported: %v (continuing)", err)
		} else if out != "" {
			opts.Log("wsl: %s", firstLine(out))
		}

		tarball, err := fetchRootfs(opts)
		if err != nil {
			return err
		}

		opts.Log("wsl: importing distro %q", opts.Distro)
		if _, err := Import(opts.Distro, filepath.Join(opts.RootDir, opts.Distro), tarball); err != nil {
			return fmt.Errorf("import distro: %w", err)
		}
	} else {
		opts.Log("wsl: distro %q already exists — reusing it", opts.Distro)
	}

	if err := enableSystemd(opts); err != nil {
		return err
	}
	if err := installAgent(opts); err != nil {
		return err
	}
	if err := runInnerBootstrap(opts); err != nil {
		return err
	}
	if err := installService(opts); err != nil {
		return err
	}
	return installAutostart(opts)
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// fetchRootfs downloads the Ubuntu rootfs, caching it so a re-provision
// after a failure does not pull 325 MB again.
func fetchRootfs(opts Options) (string, error) {
	if err := os.MkdirAll(opts.RootDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", opts.RootDir, err)
	}
	path := filepath.Join(opts.RootDir, "ubuntu-rootfs.tar.gz")

	// A previous run may have been interrupted mid-download; a truncated
	// tarball fails `wsl --import` with an unhelpful error, so treat
	// anything implausibly small as absent.
	if info, err := os.Stat(path); err == nil && info.Size() > 100<<20 {
		opts.Log("wsl: using cached rootfs (%d MB)", info.Size()>>20)
		return path, nil
	}

	opts.Log("wsl: downloading the Ubuntu rootfs (~325 MB)")
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(RootfsURL)
	if err != nil {
		return "", fmt.Errorf("download rootfs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download rootfs: %s returned %s", RootfsURL, resp.Status)
	}

	// Into a temp name first, so an interrupted download can never be
	// mistaken for a complete one by the size check above.
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write rootfs: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("finalise rootfs: %w", err)
	}
	return path, nil
}

// enableSystemd turns systemd on inside the distro and reboots it.
//
// systemd is not optional here: it is what restarts the link and the
// containers when the machine comes back. An imported rootfs has it off.
func enableSystemd(opts Options) error {
	opts.Log("wsl: enabling systemd inside %q", opts.Distro)
	if _, err := RunBash(opts.Distro, "printf '[boot]\\nsystemd=true\\n' > /etc/wsl.conf"); err != nil {
		return fmt.Errorf("write /etc/wsl.conf: %w", err)
	}
	// Only a full VM shutdown re-reads wsl.conf.
	if _, err := Shutdown(); err != nil {
		return fmt.Errorf("restart wsl: %w", err)
	}
	out, err := RunBash(opts.Distro, "ps -p 1 -o comm=")
	if err != nil {
		return fmt.Errorf("check init: %w", err)
	}
	if !strings.Contains(out, "systemd") {
		return fmt.Errorf("systemd did not come up as PID 1 inside %q (got %q) — "+
			"this needs a WSL new enough to support systemd; try `wsl --update`", opts.Distro, firstLine(out))
	}
	return nil
}

func installAgent(opts Options) error {
	opts.Log("wsl: installing aw-remote-host inside %q", opts.Distro)
	out, err := RunBash(opts.Distro, `set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || true
curl -fsSL https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.sh | sh`)
	if err != nil {
		return fmt.Errorf("install aw-remote-host inside the distro: %w", err)
	}
	opts.Log("wsl: %s", lastLineContaining(out, "installed"))
	return nil
}

func lastLineContaining(s, want string) string {
	found := ""
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, want) {
			found = strings.TrimSpace(line)
		}
	}
	if found == "" {
		return firstLine(s)
	}
	return found
}

// runInnerBootstrap links the distro and provisions the workspace in it.
//
// The token is only needed the first time: once the distro holds a durable
// credential, --with-workspace re-runs without one. Passing an empty token
// on a fresh distro fails with the CLI's own clear message, which is better
// than this package inventing a second one.
func runInnerBootstrap(opts Options) error {
	opts.Log("wsl: provisioning the workspace inside %q (podman, postgres, redis, the workspace image — several minutes)", opts.Distro)

	tokenArg := ""
	if strings.TrimSpace(opts.Token) != "" {
		tokenArg = "--token " + shellSingleQuote(opts.Token) + " "
	}
	script := fmt.Sprintf(`set -e
/root/.local/bin/aw-remote-host bootstrap-workspace %s--control-plane %s --with-workspace --yes --foreground &
BOOT_PID=$!
# The inner run holds the /link connection open forever by design, so it is
# never going to exit on its own. Wait for the module install to finish
# instead — "installed and verified" is the workspace module's last word —
# then leave it running; systemd takes ownership a step later.
for _ in $(seq 1 180); do
  if podman ps --format '{{.Names}}' 2>/dev/null | grep -q aw-remote-host-workspace; then
    echo "workspace container is up"
    exit 0
  fi
  if ! kill -0 $BOOT_PID 2>/dev/null; then
    echo "bootstrap exited before the workspace came up" >&2
    exit 1
  fi
  sleep 10
done
echo "timed out waiting for the workspace container" >&2
exit 1`, tokenArg, shellSingleQuote(opts.ControlPlane))

	out, err := RunBash(opts.Distro, script)
	if err != nil {
		return fmt.Errorf("provision workspace inside the distro: %w\n%s", err, out)
	}
	opts.Log("wsl: %s", lastLineContaining(out, "workspace"))
	return nil
}

func shellSingleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

// installService writes a systemd SYSTEM unit inside the distro.
//
// A system unit, not a --user one: root inside WSL has no user session
// ("Failed to start the systemd user session for 'root'"), so the --user
// path that internal/servicemgr uses on a normal Linux host cannot work here.
//
// Environment=HOME is load-bearing. A system unit inherits no HOME, and
// os.UserHomeDir() on Unix reads only that variable — without this the agent
// dies on startup with "$HOME is not defined" before opening a connection.
// internal/homedir now covers that too; this stays as the explicit contract.
func installService(opts Options) error {
	opts.Log("wsl: installing the systemd service inside %q", opts.Distro)
	unit := fmt.Sprintf(`[Unit]
Description=aw-remote-host - Agentic Workspace BYOD link + workspace (via WSL2)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=HOME=/root
ExecStart=/root/.local/bin/aw-remote-host bootstrap-workspace --control-plane %s --with-workspace --yes --foreground
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, opts.ControlPlane)

	script := fmt.Sprintf(`set -e
cat > /etc/systemd/system/aw-remote-host.service <<'AWEOF'
%s
AWEOF
systemctl daemon-reload
systemctl enable aw-remote-host >/dev/null 2>&1
# Hand the foreground run started during provisioning over to systemd, so
# there is exactly one process holding the link. Two would be worse than
# none: the exec job registry is per-process, so commands would land
# non-deterministically on one or the other.
pkill -f 'aw-remote-host bootstrap-workspace' || true
sleep 3
systemctl start aw-remote-host
sleep 10
systemctl is-active aw-remote-host`, unit)

	out, err := RunBash(opts.Distro, script)
	if err != nil {
		return fmt.Errorf("install systemd service: %w\n%s", err, out)
	}
	if !strings.Contains(out, "active") {
		return fmt.Errorf("systemd service did not become active: %s", firstLine(out))
	}
	return nil
}

// autostartScript is a VBScript that holds the distro open for the whole
// logon session.
//
// It must BLOCK. The obvious `wsl -d <distro> -- /bin/true` boots the distro
// and returns, and WSL then shuts an idle distro down seconds later, taking
// systemd and every container with it. That failure is genuinely hard to
// see: `wsl -l -v` reports Stopped, but any diagnostic `wsl -d …` command
// starts it again, so everything looks healthy the moment you look.
//
// VBScript rather than a .cmd because WScript.Shell.Run with a window style
// of 0 opens no window at all; a .cmd would leave a console on the desktop
// for the whole session.
const autostartScript = `' Managed by aw-remote-host. Holds the %s WSL2 distro open for this logon
' session; systemd inside it starts the link and the workspace containers.
Set sh = CreateObject("WScript.Shell")
sh.Run "wsl.exe -d %s -u root -- /bin/sh -c ""while :; do sleep 86400; done""", 0, False`

// installAutostart drops the keep-alive into the per-user Startup folder.
//
// Startup folder rather than a Scheduled Task: creating a task at the Task
// Scheduler root returns "Access is denied" without elevation, and this
// install asks for none anywhere else.
func installAutostart(opts Options) error {
	dir, err := startupFolder()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "aw-remote-host-wsl.vbs")
	body := fmt.Sprintf(autostartScript, opts.Distro, opts.Distro)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	opts.Log("wsl: autostart installed at %s", path)
	return nil
}

// startupFolder resolves the per-user Startup directory. APPDATA is set for
// any interactive Windows session; the literal path under it is fixed and
// has been since Windows 7.
func startupFolder() (string, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return "", fmt.Errorf("APPDATA is not set — cannot locate the Startup folder")
	}
	dir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return dir, nil
}
