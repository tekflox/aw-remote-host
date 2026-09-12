package bootstrap

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A module script that sources a helper it cannot find dies on the target
// machine with "No such file or directory", after the binary shipped and
// after the customer ran it. TestEveryManifestModuleIsEmbedded already guards
// the module directories themselves; nothing guarded what those scripts
// SOURCE, and bootstrap/lib is exactly where that gap lives — every new helper
// is one //go:embed line away from being absent on every host while CI stays
// green.
//
// Walking the extracted tree rather than the repo is the point: it asserts
// against the bytes that actually travel in the binary, which is the only
// filesystem the target machine ever sees.
func TestEverySourcedHelperIsEmbedded(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractScripts(dir); err != nil {
		t.Fatal(err)
	}

	// `source "$X/../lib/network.sh"` and `. "$DIR/../lib/image.sh"` — the
	// interpolated prefix varies, the lib/<name>.sh suffix does not.
	re := regexp.MustCompile(`(?m)^\s*(?:source|\.)\s+"?[^"\s]*?/(lib/[A-Za-z0-9_.-]+\.sh)"?`)

	var checked int
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".sh") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(body), -1) {
			checked++
			helper := filepath.Join(dir, m[1])
			if _, err := os.Stat(helper); err != nil {
				rel, _ := filepath.Rel(dir, path)
				t.Errorf(
					"%s sources %s, which is NOT embedded — add it to the "+
						"//go:embed line in bootstrap/embed.go, or this fails "+
						"on the host and nowhere else", rel, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A regex that silently stopped matching would turn this test into a
	// no-op that passes forever — the failure mode it exists to prevent.
	if checked == 0 {
		t.Fatal("matched no `source .../lib/*.sh` lines at all; the pattern " +
			"has drifted from the scripts and this test is now vacuous")
	}
}
