package ops

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// roundTrip uploads content through FsWriteChunk in chunks of chunkSize and
// downloads it back through FsReadChunk, returning what came back — the
// property every caller of these verbs actually depends on.
func roundTrip(t *testing.T, h *Handler, path string, content []byte, chunkSize int) []byte {
	t.Helper()
	ctx := context.Background()

	for offset := 0; ; offset += chunkSize {
		end := offset + chunkSize
		if end > len(content) {
			end = len(content)
		}
		eof := end >= len(content)
		res, err := h.FsWriteChunk(ctx, map[string]any{
			"path":   path,
			"data":   base64.StdEncoding.EncodeToString(content[offset:end]),
			"offset": float64(offset),
			"eof":    eof,
		})
		if err != nil {
			t.Fatalf("fs_write_chunk at %d: %v", offset, err)
		}
		if eof {
			want := sha256.Sum256(content)
			if got, _ := res["sha256"].(string); got != hex.EncodeToString(want[:]) {
				t.Fatalf("sha256 after upload = %q, want %q", got, hex.EncodeToString(want[:]))
			}
			break
		}
	}

	var got []byte
	for offset := 0; ; {
		res, err := h.FsReadChunk(ctx, map[string]any{
			"path": path, "offset": float64(offset), "size": float64(chunkSize),
		})
		if err != nil {
			t.Fatalf("fs_read_chunk at %d: %v", offset, err)
		}
		raw, err := base64.StdEncoding.DecodeString(res["data"].(string))
		if err != nil {
			t.Fatalf("decode chunk at %d: %v", offset, err)
		}
		got = append(got, raw...)
		offset += len(raw)
		if res["eof"] == true {
			break
		}
		if len(raw) == 0 {
			t.Fatalf("read stalled at offset %d without eof", offset)
		}
	}
	return got
}

func TestFsRoundTripMultipleChunks(t *testing.T) {
	dir := t.TempDir()
	h := &Handler{}
	// Deliberately not a multiple of the chunk size, so the final partial
	// chunk and the eof flag are both exercised.
	content := []byte(strings.Repeat("abcdefghij", 1000) + "tail")
	path := filepath.Join(dir, "nested", "deep", "payload.bin")

	got := roundTrip(t, h, path, content, 4096)
	if string(got) != string(content) {
		t.Fatalf("round trip corrupted the file: got %d bytes, want %d", len(got), len(content))
	}
	// Parent directories are created by the upload, not required to pre-exist.
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("expected parent dirs to be created: %v", err)
	}
}

func TestFsRoundTripEmptyFile(t *testing.T) {
	h := &Handler{}
	path := filepath.Join(t.TempDir(), "empty.txt")
	got := roundTrip(t, h, path, []byte{}, 4096)
	if len(got) != 0 {
		t.Fatalf("expected an empty file, got %d bytes", len(got))
	}
}

// A re-upload over a LONGER existing file must not leave the old tail behind
// — the failure mode that makes a "successful" transfer silently produce a
// corrupt file.
func TestFsWriteTruncatesLongerExistingFile(t *testing.T) {
	h := &Handler{}
	path := filepath.Join(t.TempDir(), "shrink.txt")

	roundTrip(t, h, path, []byte(strings.Repeat("X", 5000)), 4096)
	got := roundTrip(t, h, path, []byte("short"), 4096)

	if string(got) != "short" {
		t.Fatalf("re-upload left stale bytes: got %q", string(got))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 5 {
		t.Fatalf("file size after shrinking re-upload = %d, want 5", info.Size())
	}
}

func TestFsStatReportsMissingPathWithoutError(t *testing.T) {
	h := &Handler{}
	res, err := h.FsStat(context.Background(), map[string]any{
		"path": filepath.Join(t.TempDir(), "nope.txt"),
	})
	if err != nil {
		t.Fatalf("stat of a missing path should not error: %v", err)
	}
	if res["exists"] != false {
		t.Fatalf("expected exists=false, got %#v", res)
	}
}

func TestFsStatDigestMatchesContent(t *testing.T) {
	h := &Handler{}
	path := filepath.Join(t.TempDir(), "hashme.txt")
	content := []byte("hash me please")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	res, err := h.FsStat(context.Background(), map[string]any{"path": path, "want_digest": true})
	if err != nil {
		t.Fatalf("fs_stat: %v", err)
	}
	want := sha256.Sum256(content)
	if got, _ := res["sha256"].(string); got != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 = %q, want %q", got, hex.EncodeToString(want[:]))
	}
	if res["exists"] != true || res["is_dir"] != false {
		t.Fatalf("unexpected stat result %#v", res)
	}
}

func TestFsReadChunkReportsWholeFileSizeAndDigestOnFirstChunk(t *testing.T) {
	h := &Handler{}
	path := filepath.Join(t.TempDir(), "big.txt")
	content := []byte(strings.Repeat("y", 10000))
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	res, err := h.FsReadChunk(context.Background(), map[string]any{
		"path": path, "offset": float64(0), "size": float64(100), "want_digest": true,
	})
	if err != nil {
		t.Fatalf("fs_read_chunk: %v", err)
	}
	if res["size"] != int64(10000) {
		t.Fatalf("size = %#v, want the whole file size 10000", res["size"])
	}
	if res["bytes"] != 100 {
		t.Fatalf("bytes = %#v, want 100", res["bytes"])
	}
	if res["eof"] != false {
		t.Fatalf("expected eof=false on the first of many chunks, got %#v", res)
	}
	want := sha256.Sum256(content)
	if got, _ := res["sha256"].(string); got != hex.EncodeToString(want[:]) {
		t.Fatalf("first-chunk digest = %q, want %q", got, hex.EncodeToString(want[:]))
	}
}

func TestFsReadChunkPastEndIsEOFNotError(t *testing.T) {
	h := &Handler{}
	path := filepath.Join(t.TempDir(), "small.txt")
	if err := os.WriteFile(path, []byte("hi"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	res, err := h.FsReadChunk(context.Background(), map[string]any{
		"path": path, "offset": float64(9999),
	})
	if err != nil {
		t.Fatalf("reading past EOF should not error: %v", err)
	}
	if res["eof"] != true || res["bytes"] != 0 {
		t.Fatalf("expected an empty eof chunk, got %#v", res)
	}
}

func TestFsReadChunkRejectsDirectory(t *testing.T) {
	h := &Handler{}
	if _, err := h.FsReadChunk(context.Background(), map[string]any{"path": t.TempDir()}); err == nil {
		t.Fatal("expected reading a directory to fail")
	}
}

func TestFsListSortsDirsFirst(t *testing.T) {
	dir := t.TempDir()
	h := &Handler{}
	for _, name := range []string{"b.txt", "a.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "zdir"), 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}

	res, err := h.FsList(context.Background(), map[string]any{"path": dir})
	if err != nil {
		t.Fatalf("fs_list: %v", err)
	}
	entries := res["entries"].([]map[string]any)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0]["name"] != "zdir" || entries[0]["is_dir"] != true {
		t.Fatalf("expected the directory first, got %#v", entries[0])
	}
	if entries[1]["name"] != "a.txt" || entries[2]["name"] != "b.txt" {
		t.Fatalf("expected files sorted by name, got %#v", entries)
	}
	if res["truncated"] != false {
		t.Fatalf("expected truncated=false, got %#v", res["truncated"])
	}
}

func TestFsMkdirAndDelete(t *testing.T) {
	ctx := context.Background()
	h := &Handler{}
	base := t.TempDir()
	target := filepath.Join(base, "a", "b", "c")

	if _, err := h.FsMkdir(ctx, map[string]any{"path": target}); err != nil {
		t.Fatalf("fs_mkdir: %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("expected %s to be a directory: %v", target, err)
	}
	// Idempotent — MkdirAll semantics, so a second call is not an error.
	if _, err := h.FsMkdir(ctx, map[string]any{"path": target}); err != nil {
		t.Fatalf("fs_mkdir should be idempotent: %v", err)
	}

	// A non-empty directory needs an explicit recursive flag; without it the
	// caller gets an error instead of an unintended wipe.
	if _, err := h.FsDelete(ctx, map[string]any{"path": filepath.Join(base, "a")}); err == nil {
		t.Fatal("expected deleting a non-empty dir without recursive to fail")
	}
	if _, err := h.FsDelete(ctx, map[string]any{
		"path": filepath.Join(base, "a"), "recursive": true,
	}); err != nil {
		t.Fatalf("recursive fs_delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "a")); !os.IsNotExist(err) {
		t.Fatalf("expected the tree to be gone, got %v", err)
	}
}

func TestFsWriteChunkAppliesMode(t *testing.T) {
	h := &Handler{}
	path := filepath.Join(t.TempDir(), "script.sh")
	if _, err := h.FsWriteChunk(context.Background(), map[string]any{
		"path": path, "data": base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\n")),
		"eof": true, "mode": "755",
	}); err != nil {
		t.Fatalf("fs_write_chunk: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o, want 755", info.Mode().Perm())
	}
}

func TestFsWriteChunkRejectsOversizedChunk(t *testing.T) {
	h := &Handler{}
	oversized := base64.StdEncoding.EncodeToString(make([]byte, fsMaxChunk+1))
	_, err := h.FsWriteChunk(context.Background(), map[string]any{
		"path": filepath.Join(t.TempDir(), "big.bin"), "data": oversized,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected an over-limit chunk to be rejected, got %v", err)
	}
}

func TestFsVerbsRequireAPath(t *testing.T) {
	ctx := context.Background()
	h := &Handler{}
	for name, call := range map[string]func() error{
		"fs_stat":        func() error { _, err := h.FsStat(ctx, map[string]any{}); return err },
		"fs_list":        func() error { _, err := h.FsList(ctx, map[string]any{}); return err },
		"fs_mkdir":       func() error { _, err := h.FsMkdir(ctx, map[string]any{}); return err },
		"fs_delete":      func() error { _, err := h.FsDelete(ctx, map[string]any{}); return err },
		"fs_read_chunk":  func() error { _, err := h.FsReadChunk(ctx, map[string]any{}); return err },
		"fs_write_chunk": func() error { _, err := h.FsWriteChunk(ctx, map[string]any{}); return err },
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: expected an empty path to be rejected", name)
		}
	}
}

func TestExpandPathResolvesHomeRelative(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir in this environment: %v", err)
	}
	for _, tc := range []struct{ in, want string }{
		{"~", home},
		{"~/Downloads/x.txt", filepath.Join(home, "Downloads/x.txt")},
		{"Downloads/x.txt", filepath.Join(home, "Downloads/x.txt")},
		{"/etc/hosts", "/etc/hosts"},
	} {
		got, err := expandPath(tc.in)
		if err != nil {
			t.Fatalf("expandPath(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("expandPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDispatchRoutesFsVerbs(t *testing.T) {
	ctx := context.Background()
	h := &Handler{}
	path := filepath.Join(t.TempDir(), "dispatched.txt")

	if _, err := h.Dispatch(ctx, "fs_write_chunk", map[string]any{
		"path": path, "data": base64.StdEncoding.EncodeToString([]byte("via dispatch")), "eof": true,
	}, nil); err != nil {
		t.Fatalf("dispatch fs_write_chunk: %v", err)
	}
	res, err := h.Dispatch(ctx, "fs_read_chunk", map[string]any{"path": path}, nil)
	if err != nil {
		t.Fatalf("dispatch fs_read_chunk: %v", err)
	}
	data, _ := res.(map[string]any)["data"].(string)
	raw, _ := base64.StdEncoding.DecodeString(data)
	if string(raw) != "via dispatch" {
		t.Fatalf("round trip through Dispatch returned %q", string(raw))
	}
}
