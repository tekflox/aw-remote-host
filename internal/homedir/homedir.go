// Package homedir resolves this process's home directory, which every part
// of this CLI needs — credentials.json, state.json, the bootstrap script
// extract dir, the service definitions and the TLS cache all live under it.
//
// It exists because os.UserHomeDir() alone is not enough. On Unix that
// function reads $HOME and nothing else, returning "$HOME is not defined"
// when the variable is absent — and a **systemd system unit does not set
// $HOME**. (A user unit does, which is why this never surfaced: the systemd
// path in internal/servicemgr writes a --user unit.)
//
// That failure was found the hard way: aw-remote-host running from a system
// unit inside a WSL2 distro died instantly with
//
//	aw-remote-host: resolve home dir: $HOME is not defined
//
// having never opened a connection. It is not WSL-specific — any Linux host
// running this from /etc/systemd/system, from cron, or from an init script
// hits exactly the same wall.
package homedir

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
)

// Dir returns the home directory, falling back to the account database when
// the environment does not carry it.
//
// The fallback is deliberately second, not first: $HOME is what the user
// (or the service definition) explicitly asked for, and honouring an
// overridden HOME is how tests and unusual deployments point this CLI at a
// different directory. Only when there is no answer at all does this consult
// the passwd entry, which is where the real home lives regardless of
// environment.
func Dir() (string, error) {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home, nil
	}

	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir, nil
	}

	// Last resort on Unix: a service running as root with neither $HOME nor
	// a resolvable passwd entry (a stripped container image, say) still has
	// a conventional answer, and failing here would take the whole process
	// down over a directory everyone knows.
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return "/root", nil
	}

	return "", fmt.Errorf("resolve home dir: $HOME is not set and no account entry was found for this user")
}
