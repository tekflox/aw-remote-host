//go:build !windows

package diagdump

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Start arms the SIGUSR1 handler and runs until ctx is done. Safe to call
// once per process (typically from the same place that builds the SIGTERM/
// SIGINT NotifyContext) — each SIGUSR1 received logs every goroutine's
// stack via rlog.Printf (console + the rotating client.log file) and then
// goes right back to waiting for the next one, unlike SIGQUIT which never
// returns.
func Start(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)

	go func() {
		defer signal.Stop(sigCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				dump()
			}
		}
	}()
}
