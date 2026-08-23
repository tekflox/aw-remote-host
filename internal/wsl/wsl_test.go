package wsl

import "testing"

// wsl.exe writes UTF-16LE. Left undecoded, "aw-ubuntu" arrives as
// "a\0w\0-\0u\0..." and every substring match silently fails — which is how
// a distro that plainly exists reads as missing.
func TestDecodeOutputHandlesUTF16(t *testing.T) {
	utf16le := []byte{0xFF, 0xFE}
	for _, r := range "aw-ubuntu" {
		utf16le = append(utf16le, byte(r), 0x00)
	}
	if got := decodeOutput(utf16le); got != "aw-ubuntu" {
		t.Errorf("decodeOutput(utf16) = %q, want %q", got, "aw-ubuntu")
	}
}

func TestDecodeOutputLeavesPlainASCIIAlone(t *testing.T) {
	if got := decodeOutput([]byte("already ascii\nsecond line")); got != "already ascii\nsecond line" {
		t.Errorf("decodeOutput(ascii) = %q", got)
	}
}

func TestDecodeOutputWithoutBOM(t *testing.T) {
	// wsl does not always emit a BOM, so the heuristic has to carry it.
	var b []byte
	for _, r := range "Stopped" {
		b = append(b, byte(r), 0x00)
	}
	if got := decodeOutput(b); got != "Stopped" {
		t.Errorf("decodeOutput(no BOM) = %q, want %q", got, "Stopped")
	}
}

func TestShellSingleQuote(t *testing.T) {
	if got := shellSingleQuote(`a'b`); got != `'a'"'"'b'` {
		t.Errorf("shellSingleQuote = %q", got)
	}
	if got := shellSingleQuote("https://api.aw.tekflox.com"); got != "'https://api.aw.tekflox.com'" {
		t.Errorf("shellSingleQuote(url) = %q", got)
	}
}

func TestFirstLineSkipsBlanks(t *testing.T) {
	if got := firstLine("\n\n  real line  \nnext"); got != "real line" {
		t.Errorf("firstLine = %q", got)
	}
}

func TestLastLineContaining(t *testing.T) {
	out := "downloading\ninstalled v0.1.40\nnote: PATH"
	if got := lastLineContaining(out, "installed"); got != "installed v0.1.40" {
		t.Errorf("lastLineContaining = %q", got)
	}
	// Falls back to something rather than empty, so a log line is never blank.
	if got := lastLineContaining("only line", "absent"); got != "only line" {
		t.Errorf("fallback = %q", got)
	}
}
