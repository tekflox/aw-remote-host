//go:build windows

package main

import "golang.org/x/sys/windows"

// isElevated reports whether this process holds an elevated token.
//
// The token's own elevation flag, not a "am I in the Administrators group"
// check — those answer different questions and the difference is the whole
// point of UAC. An admin user's normal shell IS in the group and still runs
// with a filtered token that cannot restart a service, so a group check
// would wave through exactly the case this guard exists to catch.
func isElevated() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}
