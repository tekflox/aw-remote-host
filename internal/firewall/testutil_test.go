package firewall

import (
	"context"
	"strings"
)

// fakeRunner mirrors internal/ops's own test helper (same shape, separate
// package) — records every invocation and returns scripted output/errors
// per exact argv, so tests never touch a real iptables/nft binary.
type fakeRunner struct {
	calls   [][]string
	outputs map[string]string
	errs    map[string]error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]string{}, errs: map[string]error{}}
}

func (f *fakeRunner) key(name string, args ...string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

func (f *fakeRunner) on(output string, name string, args ...string) {
	f.outputs[f.key(name, args...)] = output
}

func (f *fakeRunner) fail(err error, name string, args ...string) {
	f.errs[f.key(name, args...)] = err
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	k := f.key(name, args...)
	if err, ok := f.errs[k]; ok {
		return f.outputs[k], err
	}
	return f.outputs[k], nil
}

// callsWithPrefix returns every recorded call whose ARGUMENTS (the binary
// name itself, e.g. "iptables"/"nft", is not part of the match) start with
// prefix — used to assert on the shape of a backend's generated argv
// without pinning down every unrelated call.
func (f *fakeRunner) callsWithPrefix(prefix ...string) [][]string {
	var out [][]string
	for _, c := range f.calls {
		args := c[1:]
		if len(args) < len(prefix) {
			continue
		}
		match := true
		for i, p := range prefix {
			if args[i] != p {
				match = false
				break
			}
		}
		if match {
			out = append(out, c)
		}
	}
	return out
}
