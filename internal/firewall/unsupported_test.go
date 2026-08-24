package firewall

import (
	"context"
	"testing"
)

func TestUnsupportedBackend(t *testing.T) {
	b := unsupportedBackend{reason: "host OS is darwin — firewall management is Linux-only in v1"}

	name, privileged, reason, err := b.Probe(context.Background())
	if err != nil || name != "unsupported" || privileged || reason == "" {
		t.Fatalf("Probe = (%q, %v, %q, %v), want (unsupported, false, non-empty, nil)", name, privileged, reason, err)
	}

	if err := b.Apply(context.Background(), nil, false); err == nil {
		t.Fatalf("Apply must fail on an unsupported host, not pretend to succeed")
	}

	st, err := b.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Backend != "unsupported" || st.Privileged || st.PrivilegedReason == "" {
		t.Fatalf("Status = %+v, want backend=unsupported privileged=false with a reason", st)
	}
}
