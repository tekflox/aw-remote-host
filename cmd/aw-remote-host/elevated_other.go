//go:build !windows

package main

// isElevated is Windows-only in meaning. The --elevated flag rejects
// non-Windows before ever calling this, but the symbol has to exist for the
// package to build on macOS and Linux — where the caller has already
// returned an error, so the value is never consulted.
func isElevated() bool { return false }
