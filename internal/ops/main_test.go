package ops

import (
	"os"
	"testing"
)

// TestMain redirects $HOME for the WHOLE package, so no test in it can reach
// the real “~/.aw-remote-host“.
//
// This became load-bearing when Dispatch started taking the per-MACHINE
// workspace-lifecycle flock for the recreate verbs (workspace_lock_unix.go):
// “instance.MachineDir()“ resolves off $HOME, and several pre-existing
// tests here drive “Dispatch(ctx, "bootstrap", ...)“ deliberately — the
// routing is part of what they cover. Those tests had no reason to isolate
// $HOME before, and silently started contending for the real machine lock
// the moment the lock existed. Caught by the lockfile appearing in the real
// “~/.aw-remote-host“ after a plain “go test ./...“.
//
// Why that is not merely untidy: this repo's CI runs on “[self-hosted,
// aw-baremetal]“ — the production host. The interference goes both ways. A
// test run could take the real lock and refuse a genuine console Update, and
// a genuine in-flight update would make those tests fail with
// errWorkspaceBusy instead of dispatching. Neither is acceptable, and both
// would present as a flake.
//
// Package-level rather than one “t.Setenv“ per test on purpose: the next
// test that dispatches a recreate verb is isolated automatically instead of
// having to remember. Individual tests that need a specific HOME still
// override it with “t.Setenv“ as several already do — t.Setenv is
// per-test and takes precedence over what is set here.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "aw-remote-host-ops-test-home-")
	if err != nil {
		panic("create temp HOME for the ops test suite: " + err.Error())
	}
	// Not t.Setenv (no *testing.T here) and not deferred — os.Exit below
	// does not run defers, so the cleanup is explicit and before it.
	if err := os.Setenv("HOME", home); err != nil {
		panic("redirect HOME for the ops test suite: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
