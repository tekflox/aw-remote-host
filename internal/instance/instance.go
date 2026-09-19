// Package instance splits this client's state tree by LIFETIME, which is
// the whole of what makes "one physical machine, two tenant identities"
// safe rather than merely possible.
//
// ~/.aw-remote-host/ used to be flat, and held two kinds of state side by
// side:
//
//   - PER-IDENTITY — credentials.json, state.json, the service definition
//     and its logs, client.log. One per account this machine serves.
//   - PER-MACHINE — firewall.json, vpn-deadman.json, self-update/. One per
//     BOX, no matter how many accounts it serves: there is one firewall,
//     one VPN kill-switch and one binary on this host.
//
// The obvious lever for a second identity — overriding $HOME for the whole
// process, which is what was done by hand before this existed — isolates
// BOTH halves. That leaves two VPN dead-man switches and two self-updaters
// each believing they own the machine, which is a worse bug than the one it
// works around, and it also drags podman's storage root, the Go cache and
// ssh along with it. So the lever here is narrow on purpose: Dir(name)
// moves, MachineDir() never does.
//
// The DEFAULT (unnamed) instance resolves to the flat, historical path,
// byte for byte. That is not a convenience — every BYOD host in the field
// is an unnamed instance, and a change that relocated their state (or
// renamed their service unit) would orphan every one of them on upgrade.
package instance

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/tekflox/aw-remote-host/internal/homedir"
)

const (
	rootDirName      = ".aw-remote-host"
	instancesDirName = "instances"

	// DefaultName is the name a user can type to mean "the default,
	// unnamed instance" — i.e. the flat paths this client has always
	// used. It normalizes to the empty string, so nothing downstream ever
	// sees a directory or a unit named "default".
	//
	// It exists for exactly one reason: the second-link refusal in the
	// link command needs a way for an operator to say "yes, I really do
	// mean to re-link THIS machine's existing identity with a fresh
	// token", which is otherwise indistinguishable from the mistake the
	// refusal is there to catch.
	DefaultName = "default"
)

var (
	activeMu sync.RWMutex
	active   string
)

// SetActive records which instance this PROCESS is running as. Called once,
// right after the --instance flag is parsed, before anything resolves a
// path.
//
// A process-global rather than a parameter threaded through every helper
// because one process only ever serves one identity: the daemon started by
// `link --instance work` is that identity for its whole life, and the
// alternative is threading a name through the ~13 call sites of
// state.DefaultPath() alone, where a single missed one silently shares
// state between two accounts. Partial threading is worse than none.
//
// name is normalized, so SetActive("default") is the same as SetActive("").
func SetActive(name string) {
	activeMu.Lock()
	defer activeMu.Unlock()
	active = Normalize(name)
}

// Active returns this process's instance name — "" for the default one.
func Active() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return active
}

// ActiveDir is Dir(Active()).
func ActiveDir() (string, error) {
	return Dir(Active())
}

// Normalize trims a user-supplied name and maps the reserved DefaultName
// onto "" — the default instance.
func Normalize(name string) string {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, DefaultName) {
		return ""
	}
	return name
}

// Validate reports whether a user-supplied name is usable as an instance.
//
// Deliberately strict: this name becomes a directory component, a systemd
// unit name and a launchd label, and a name that is legal in one of those
// and not the others fails somewhere far from where it was typed.
func Validate(name string) error {
	name = Normalize(name)
	if name == "" {
		return nil // the default instance
	}
	if len(name) > 64 {
		return fmt.Errorf("instance name %q is too long (max 64 characters)", name)
	}
	for i, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok && i > 0 {
			ok = r == '-' || r == '_'
		}
		if !ok {
			return fmt.Errorf("invalid instance name %q: use letters, digits, '-' and '_', starting with a letter or digit", name)
		}
	}
	return nil
}

// MachineDir returns ~/.aw-remote-host — the PER-MACHINE state root. It is
// the same directory for every instance on this host, by design: see the
// package doc.
func MachineDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, rootDirName), nil
}

// Dir returns the PER-IDENTITY state directory for name.
//
// The default instance ("") resolves to MachineDir() itself — the flat
// layout every existing host already has on disk. A named instance gets
// ~/.aw-remote-host/instances/<name>/.
func Dir(name string) (string, error) {
	root, err := MachineDir()
	if err != nil {
		return "", err
	}
	name = Normalize(name)
	if name == "" {
		return root, nil
	}
	if err := Validate(name); err != nil {
		return "", err
	}
	return filepath.Join(root, instancesDirName, name), nil
}

// List returns the NAMED instances that exist on this machine, sorted. The
// default instance is never in it — it has no directory of its own, it IS
// the root.
//
// Used by `status` to tell an operator how many identities the box in front
// of them is actually serving, which is otherwise invisible.
func List() ([]string, error) {
	root, err := MachineDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, instancesDirName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read instances dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
