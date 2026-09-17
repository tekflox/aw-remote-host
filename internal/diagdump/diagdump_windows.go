//go:build windows

package diagdump

import "context"

// Start is a no-op on Windows: os/signal has no SIGUSR1 there, and the
// hosted container form this dump exists for is Linux-only anyway — a
// Windows BYOD host's workspace runs inside the WSL2 distro internal/wsl
// provisions (an ordinary Linux node), which is where this would need to be
// armed instead, same reasoning as internal/vpn/deadman_windows.go. This
// exists purely so the binary still cross-compiles for windows/amd64 and
// windows/arm64, which the release workflow builds.
func Start(ctx context.Context) {}
