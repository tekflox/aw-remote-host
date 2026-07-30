package bootstrap

import "testing"

func TestEnvPassthroughIncludesConfiguredValues(t *testing.T) {
	t.Setenv("AW_WORKSPACE_IMAGE", "aw-workspace:e2e")
	t.Setenv("EMPTY_VALUE", "")

	got := EnvPassthrough("AW_WORKSPACE_IMAGE", "EMPTY_VALUE", "MISSING_VALUE")
	want := []string{"AW_WORKSPACE_IMAGE=aw-workspace:e2e"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("EnvPassthrough() = %#v, want %#v", got, want)
	}
}
