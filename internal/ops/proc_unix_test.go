//go:build !windows

package ops

import "testing"

func TestShellCommandPOSIX(t *testing.T) {
	name, args := shellCommand("echo hi")
	if name != "sh" {
		t.Errorf("shell = %q, want sh", name)
	}
	if len(args) != 2 || args[0] != "-c" || args[1] != "echo hi" {
		t.Errorf("args = %q, want [-c echo hi]", args)
	}
}

// The Windows twin sets this false, which is what makes Dispatch refuse the
// podman-backed verbs there. Asserting the POSIX value keeps a future edit
// from flipping it and silently disabling every lifecycle verb on Linux.
func TestWorkspaceRuntimeSupportedOnPOSIX(t *testing.T) {
	if !workspaceRuntimeSupported {
		t.Error("POSIX hosts must keep the workspace lifecycle verbs enabled")
	}
}

// The guard in Dispatch is only reachable on Windows, but the verb list it
// consults is shared — so at least pin its membership. exec_*/fs_* must
// never be in it: those are the whole point of a lean Windows link.
func TestWorkspaceLifecycleVerbsMembership(t *testing.T) {
	for _, verb := range []string{"stop", "restart", "uninstall", "reinstall", "bootstrap", "update"} {
		if !workspaceLifecycleVerbs[verb] {
			t.Errorf("%q should be gated behind a local workspace runtime", verb)
		}
	}
	for _, verb := range []string{
		"exec_start", "exec_status", "exec_wait", "exec_kill", "list_processes",
		"fs_stat", "fs_list", "fs_mkdir", "fs_delete", "fs_read_chunk", "fs_write_chunk",
		// health degrades to {"offline": true} by itself — gating it would
		// turn an honest "no workspace here" into a tunnel-level error.
		"health",
		// "self-update" drives the aw-remote-host BINARY, not the podman
		// workspace container, so the runtime gate never applied to it. It
		// used to be in the list above, which is precisely what made a lean
		// host — every Windows host, and a podman-less Linux one — unable to
		// update itself from the console: it was refused with "needs the
		// local workspace runtime", a true statement about the workspace and
		// an irrelevant one about replacing a binary.
		"self-update",
	} {
		if workspaceLifecycleVerbs[verb] {
			t.Errorf("%q must stay available on a host with no workspace runtime", verb)
		}
	}
}
