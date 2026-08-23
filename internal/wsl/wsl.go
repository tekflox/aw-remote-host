// Package wsl drives wsl.exe from Windows so a Windows host can provision
// and run a workspace after all.
//
// A Windows machine cannot host the workspace directly — the image is a
// Linux container — but it can host a WSL2 distro that does, and inside that
// distro everything is an ordinary Linux BYOD host. This package is the
// bridge: it stands the distro up, puts the Linux aw-remote-host inside it,
// and arranges for both to come back at logon.
//
// Every step here was first performed by hand against a real Windows 10 host
// before being written down, which is why the comments dwell on failure
// modes rather than on what the commands do.
package wsl

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf16"
)

// DefaultDistro is the distro name this CLI owns. Deliberately not "Ubuntu":
// a machine may already have an Ubuntu distro that belongs to its owner, and
// importing over it would be destructive.
const DefaultDistro = "aw-ubuntu"

// RootfsURL is the official Ubuntu 22.04 WSL rootfs.
//
// Note the filename: `-ubuntu22.04lts.rootfs.tar.gz`, NOT the `-wsl.rootfs`
// form that older docs use — that one 404s. 24.04 (noble) would be
// preferable, since it ships podman 4.x and skips the CNI repair in
// bootstrap/lib/network.sh entirely, but Canonical no longer publishes a
// noble rootfs at cloud-images.
const RootfsURL = "https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-ubuntu22.04lts.rootfs.tar.gz"

// decodeOutput converts wsl.exe's output to a normal Go string.
//
// wsl.exe writes **UTF-16LE**, so its output arrives with a NUL between
// every character. Left alone it looks like a corrupted transport rather
// than an encoding — `wsl -l -v` comes back as "a w - u b u n t u" — and
// every substring match silently fails.
func decodeOutput(b []byte) string {
	b = bytes.TrimPrefix(b, []byte{0xFF, 0xFE})
	if len(b) < 2 || !looksUTF16(b) {
		return string(b)
	}
	codes := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		codes = append(codes, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(codes))
}

// looksUTF16 reports whether b is plausibly UTF-16LE ASCII text — every
// other byte a NUL. Cheap and good enough: the alternative is trusting a
// BOM that wsl.exe does not always emit.
func looksUTF16(b []byte) bool {
	n := len(b)
	if n > 64 {
		n = 64
	}
	nuls := 0
	for i := 1; i < n; i += 2 {
		if b[i] == 0 {
			nuls++
		}
	}
	return nuls > n/4
}

func run(args ...string) (string, error) {
	out, err := exec.Command("wsl.exe", args...).CombinedOutput()
	text := strings.TrimSpace(decodeOutput(out))
	if err != nil {
		return text, fmt.Errorf("wsl %s: %w: %s", strings.Join(args, " "), err, text)
	}
	return text, nil
}

// Available reports whether wsl.exe exists at all.
func Available() error {
	if _, err := exec.LookPath("wsl.exe"); err != nil {
		return fmt.Errorf("wsl.exe not found — Windows Subsystem for Linux is not installed. " +
			"Install it with `wsl --install` from an elevated PowerShell, then re-run this")
	}
	return nil
}

// DistroExists reports whether a distro of this name is registered.
func DistroExists(name string) (bool, error) {
	out, err := run("-l", "-q")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), name) {
			return true, nil
		}
	}
	return false, nil
}

// UpdateKernel runs `wsl --update`.
//
// Worth doing unconditionally on first provision: a machine that has had WSL
// installed for years can still be on a 2020-era kernel (4.19 was found on
// the first real host), which is old enough that modern distros misbehave in
// ways that look like application bugs.
func UpdateKernel() (string, error) {
	return run("--update")
}

// Import registers a distro from a rootfs tarball.
//
// Import rather than `wsl --install -d Ubuntu`: --install LAUNCHES the distro
// and blocks asking for a username and password, which hangs any
// non-interactive run until its timeout. An imported distro's default user
// is root and no prompt ever appears.
func Import(name, installDir, tarball string) (string, error) {
	return run("--import", name, installDir, tarball, "--version", "2")
}

// Shutdown stops every distro and the WSL2 VM itself. Needed after writing
// /etc/wsl.conf, since systemd only takes effect on a fresh boot.
func Shutdown() (string, error) {
	return run("--shutdown")
}

// RunBash executes a bash script inside the distro as root.
//
// The script travels **base64-encoded**, which is not paranoia: the argument
// crosses Go's argv escaping, then Windows' command-line parsing, then wsl's,
// then bash's. Anything with a quote, a `$` or a newline is mangled somewhere
// in that chain — a heredoc writing `[boot]\nsystemd=true` came out the other
// side as a PowerShell array index. Base64 has no metacharacters, so there is
// nothing left to mangle.
func RunBash(distro, script string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	return run("-d", distro, "-u", "root", "--",
		"bash", "-c", "echo "+encoded+" | base64 -d | bash")
}
