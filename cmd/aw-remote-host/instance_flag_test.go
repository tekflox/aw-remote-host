package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tekflox/aw-remote-host/internal/instance"
	"github.com/tekflox/aw-remote-host/internal/link"
)

// isolateHome points this process at a throwaway home AND resets the
// process-global active instance afterwards.
//
// The reset is not hygiene, it is correctness: instance.Active() is a
// process global (one process serves one identity), so a test that left it
// set would silently redirect every later test's paths.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Cleanup(func() { instance.SetActive("") })
	return home
}

// TestBootstrapWorkspaceRefusesANamedInstance is refusal 1: a second FULL
// workspace on one machine. It must fail BEFORE any state is written and
// before podman is invoked, and the message must name the collision rather
// than leaving the operator with a half-built runtime to clean up.
func TestBootstrapWorkspaceRefusesANamedInstance(t *testing.T) {
	home := isolateHome(t)

	err := runBootstrapWorkspace([]string{"--instance", "work", "--with-workspace", "--yes", "--token", "awbs_x"})
	if err == nil {
		t.Fatal("bootstrap-workspace accepted a named instance; a second full workspace would take the first one's containers")
	}
	msg := err.Error()
	for _, want := range []string{
		"aw-remote-host-workspace", // the container collision
		"127.0.0.1:9030",           // the port collision
		"podman network",           // the network collision
		"link --token <token> --instance work",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q:\n%s", want, msg)
		}
	}

	// Nothing may have been written — not the instance dir, not the state
	// tree at all. A refusal that already created files is not a refusal.
	if _, statErr := os.Stat(filepath.Join(home, ".aw-remote-host")); !os.IsNotExist(statErr) {
		t.Errorf("the refusal wrote state before refusing (%v)", statErr)
	}
}

// TestSecondLinkWithoutInstanceIsRefused is refusal 2, and the one this
// feature is actually discovered through.
//
// The console's generated link command does not carry --instance, so an
// operator linking a second account pastes a command with none onto a
// machine that already has an identity. Before this, that paste SILENTLY
// succeeded as the wrong account: link.Client.Run prefers a stored host
// credential over the --token it was handed, so the new account's token was
// never redeemed and the machine stayed registered as the first one.
func TestSecondLinkWithoutInstanceIsRefused(t *testing.T) {
	home := isolateHome(t)

	credPath := filepath.Join(home, ".aw-remote-host", "credentials.json")
	if err := link.SaveCredentials(credPath, &link.Credentials{
		RemoteHostID: "id16", HostCredential: "awlk_first_account",
	}); err != nil {
		t.Fatal(err)
	}

	err := runLink([]string{"--token", "awbs_second_account", "--yes"})
	if err == nil {
		t.Fatal("a second link with no --instance was accepted; it would silently stay registered as the FIRST account")
	}
	msg := err.Error()
	// The PO's requirement, verbatim: the error must name the flag and show
	// the corrected command. This error text is the ONLY discovery path for
	// the feature in v1.
	for _, want := range []string{
		"--instance <name>",
		"link --token <token> --instance <name>",
		"--instance default", // the escape hatch for re-linking this identity
		credPath,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q:\n%s", want, msg)
		}
	}

	// The first account's credential must be exactly as it was.
	creds, loadErr := link.LoadCredentials(credPath)
	if loadErr != nil || creds == nil || creds.HostCredential != "awlk_first_account" {
		t.Errorf("the refused link touched the existing identity's credentials: %+v (%v)", creds, loadErr)
	}
}

// TestExplicitInstanceDefaultIsNotRefused covers the escape hatch. Without
// it, refusal 2 would make it impossible to re-link a machine whose stored
// credential has gone stale (after a workspace reset, say) without a full
// unlink — turning a guard into a trap.
//
// It gets past the refusal, so it fails later, on the network. That is the
// assertion: the error must not be the refusal.
func TestExplicitInstanceDefaultIsNotRefused(t *testing.T) {
	home := isolateHome(t)

	credPath := filepath.Join(home, ".aw-remote-host", "credentials.json")
	if err := link.SaveCredentials(credPath, &link.Credentials{
		RemoteHostID: "id16", HostCredential: "awlk_stale",
	}); err != nil {
		t.Fatal(err)
	}

	err := runLink([]string{"--token", "awbs_fresh", "--yes", "--instance", "default", "--plan"})
	if err != nil {
		t.Fatalf("--instance default was refused: %v", err)
	}
	if got := instance.Active(); got != "" {
		t.Errorf("--instance default resolved to %q, want the default instance", got)
	}
}

func TestInstanceFlagValidationRefusesUnusableNames(t *testing.T) {
	isolateHome(t)
	// "../escape" would put this identity's credentials outside the state
	// tree entirely; the others break a systemd unit name or a launchd label.
	for _, bad := range []string{"../escape", "a/b", "has space", "-leading"} {
		if err := runStatus([]string{"--instance", bad}); err == nil {
			t.Errorf("status accepted --instance %q", bad)
		}
	}
}

// TestNamedInstanceIsRefusedOnWindows pins the product decision that every
// platform is explicitly supported or explicitly refused. On a non-Windows
// build there is nothing to assert beyond "the flag is accepted", which the
// tests above already cover.
func TestNamedInstanceIsRefusedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the refusal is GOOS-gated; the servicemgr half is asserted from any host by TestSchtasksRefusesANamedInstance")
	}
	isolateHome(t)
	err := runStatus([]string{"--instance", "work"})
	if err == nil || !strings.Contains(err.Error(), "not supported on Windows") {
		t.Errorf("Windows must refuse a named instance outright, got %v", err)
	}
}
