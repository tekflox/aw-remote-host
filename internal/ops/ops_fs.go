// File-transfer and filesystem-inspection verbs, added alongside the exec
// verbs in ops_exec.go.
//
// Design note — why these ride the existing "cmd" channel instead of new
// frame types: the monolith's remote-agent (agents-platform-legacy's
// backend/app/api/remote_agents.py) grew a dedicated pair of async frame
// families for this (fs_write_chunk/fs_write_chunk_ack, fs_read_request/
// fs_read_chunk) because the control plane pushed chunks at the client
// without waiting. That shape needs its own correlation table, its own
// timeout handling, and — here — its own path through aw-backend's
// cross-worker relay, none of which the cmd channel would have needed:
// send_command_anywhere already correlates, times out, and relays. So every
// verb below is an ordinary request/response cmd, and bulk transfer is
// expressed as a SEQUENCE of them, each carrying one bounded chunk at an
// explicit offset.
//
// The cost is that chunks are sequential (one round-trip each) rather than
// pipelined, so throughput is latency-bound: ~fsDefaultChunk per RTT. At a
// 1 MiB chunk and a 50ms round trip that is ~20 MB/s, which is well past
// what the far side of a home uplink delivers anyway. The gain is that a
// transfer is stateless on the host: every write carries its own offset, so
// there is no half-open file handle to leak when a link drops mid-transfer,
// and a resumed/retried chunk is idempotent.
package ops

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// fsDefaultChunk is used when the caller doesn't pass "size" on a read.
	fsDefaultChunk = 1 << 20 // 1 MiB
	// fsMaxChunk caps a single chunk in either direction. A cmd frame is one
	// JSON message over the /link WebSocket, and base64 inflates by 4/3 —
	// 4 MiB raw lands around 5.6 MiB on the wire, comfortably under the 16 MiB
	// default max message size uvicorn's websockets implementation enforces on
	// the control-plane side. Raising this past that limit would not fail
	// gracefully: the server closes the connection.
	fsMaxChunk = 4 << 20 // 4 MiB
	// fsDigestMaxSize bounds whole-file sha256 verification. Hashing re-reads
	// the entire file, so past this size the digest is SKIPPED and explicitly
	// reported as skipped (digest_skipped: true) rather than silently omitted —
	// a caller must be able to tell "verified" from "not checked".
	fsDigestMaxSize = 2 << 30 // 2 GiB
	// fsListMaxEntries bounds one fs_list reply so a directory with a million
	// entries can't produce an unbounded frame. Truncation is reported.
	fsListMaxEntries = 2000
)

// expandPath resolves a caller-supplied path the way a shell would: "~" and
// "~/x" against this user's home, and a RELATIVE path against home too
// rather than against this process's working directory — the daemon's cwd is
// wherever systemd/launchd started it, which is never what a human typing
// "pull Downloads/report.pdf" means.
func expandPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("path is required")
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		if p == "~" {
			return home, nil
		}
		return filepath.Join(home, p[2:]), nil
	}
	if !filepath.IsAbs(p) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		return filepath.Join(home, p), nil
	}
	return filepath.Clean(p), nil
}

func boolArg(args map[string]any, key string, def bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return def
}

// fileDigest streams the file through sha256 without holding it in memory.
// Returns ("", true, nil) — empty digest, skipped=true — for a file past
// fsDigestMaxSize, so the caller reports "not checked" instead of "verified".
func fileDigest(path string, size int64) (digest string, skipped bool, err error) {
	if size > fsDigestMaxSize {
		return "", true, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false, fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), false, nil
}

func fileInfoMap(path string, info os.FileInfo) map[string]any {
	return map[string]any{
		"name":        info.Name(),
		"path":        path,
		"is_dir":      info.IsDir(),
		"size":        info.Size(),
		"mode":        fmt.Sprintf("%04o", info.Mode().Perm()),
		"modified_at": info.ModTime().Unix(),
	}
}

// FsStat reports whether a path exists and what it is. args: "path"
// (required), "want_digest" (optional — sha256 of a regular file).
//
// A missing path is NOT an error: it returns {exists: false}, because "does
// this exist?" is the question the verb answers, and making absence an error
// would force every caller to string-match the message to tell it apart from
// a permission failure (which IS an error).
func (h *Handler) FsStat(ctx context.Context, args map[string]any) (map[string]any, error) {
	path, err := expandPath(stringArg(args, "path"))
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return map[string]any{"path": path, "exists": false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	out := fileInfoMap(path, info)
	out["exists"] = true
	if boolArg(args, "want_digest", false) && info.Mode().IsRegular() {
		digest, skipped, err := fileDigest(path, info.Size())
		if err != nil {
			return nil, err
		}
		if skipped {
			out["digest_skipped"] = true
		} else {
			out["sha256"] = digest
		}
	}
	return out, nil
}

// FsList enumerates a directory. args: "path" (required).
func (h *Handler) FsList(ctx context.Context, args map[string]any) (map[string]any, error) {
	path, err := expandPath(stringArg(args, "path"))
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", path, err)
	}

	truncated := false
	if len(entries) > fsListMaxEntries {
		entries = entries[:fsListMaxEntries]
		truncated = true
	}

	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			// A file deleted between ReadDir and Info is normal on a live
			// filesystem — skip it rather than failing the whole listing.
			continue
		}
		out = append(out, fileInfoMap(filepath.Join(path, e.Name()), info))
	}
	// Directories first, then name — the ordering a human scanning `ls` output
	// expects, and stable across platforms (ReadDir is only sorted by name).
	sort.SliceStable(out, func(i, j int) bool {
		di, _ := out[i]["is_dir"].(bool)
		dj, _ := out[j]["is_dir"].(bool)
		if di != dj {
			return di
		}
		ni, _ := out[i]["name"].(string)
		nj, _ := out[j]["name"].(string)
		return ni < nj
	})

	return map[string]any{
		"path": path, "entries": out, "count": len(out), "truncated": truncated,
	}, nil
}

// FsMkdir creates a directory and any missing parents. args: "path"
// (required). Succeeds if it already exists (MkdirAll semantics).
func (h *Handler) FsMkdir(ctx context.Context, args map[string]any) (map[string]any, error) {
	path, err := expandPath(stringArg(args, "path"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", path, err)
	}
	return map[string]any{"path": path, "created": true}, nil
}

// FsDelete removes a file or directory. args: "path" (required),
// "recursive" (optional — required to remove a non-empty directory; without
// it a non-empty directory is an error rather than a surprise wipe).
func (h *Handler) FsDelete(ctx context.Context, args map[string]any) (map[string]any, error) {
	path, err := expandPath(stringArg(args, "path"))
	if err != nil {
		return nil, err
	}
	if boolArg(args, "recursive", false) {
		if err := os.RemoveAll(path); err != nil {
			return nil, fmt.Errorf("delete %s: %w", path, err)
		}
	} else if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("delete %s: %w", path, err)
	}
	return map[string]any{"path": path, "deleted": true}, nil
}

// FsReadChunk reads one bounded window of a file — the download primitive.
// args: "path" (required), "offset" (default 0), "size" (default
// fsDefaultChunk, capped at fsMaxChunk), "want_digest" (optional; the caller
// asks for it on the FIRST chunk so the control plane can publish a verified
// digest in a response header before it has streamed the body).
//
// Returns {data (base64), bytes, offset, size (of the WHOLE file), eof}.
// eof is computed from the file's size, so a caller loops until eof rather
// than guessing from a short read.
func (h *Handler) FsReadChunk(ctx context.Context, args map[string]any) (map[string]any, error) {
	path, err := expandPath(stringArg(args, "path"))
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("read %s: is a directory", path)
	}

	offset := int64(floatArg(args, "offset", 0))
	if offset < 0 {
		return nil, fmt.Errorf("offset must not be negative")
	}
	size := int64(floatArg(args, "size", fsDefaultChunk))
	if size <= 0 {
		size = fsDefaultChunk
	}
	if size > fsMaxChunk {
		size = fsMaxChunk
	}

	out := map[string]any{
		"path": path, "offset": offset, "size": info.Size(),
	}
	if boolArg(args, "want_digest", false) {
		digest, skipped, err := fileDigest(path, info.Size())
		if err != nil {
			return nil, err
		}
		if skipped {
			out["digest_skipped"] = true
		} else {
			out["sha256"] = digest
		}
	}

	// Reading at or past EOF is not an error — it is how a zero-byte file, or
	// a caller that asked for one chunk too many, terminates the loop.
	if offset >= info.Size() {
		out["data"] = ""
		out["bytes"] = 0
		out["eof"] = true
		return out, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if remaining := info.Size() - offset; size > remaining {
		size = remaining
	}
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read %s at %d: %w", path, offset, err)
	}
	buf = buf[:n]

	out["data"] = base64.StdEncoding.EncodeToString(buf)
	out["bytes"] = n
	out["eof"] = offset+int64(n) >= info.Size()
	return out, nil
}

// FsWriteChunk writes one bounded window of a file — the upload primitive.
// args: "path" (required), "data" (base64, may be empty), "offset" (default
// 0), "eof" (optional — finalizes), "mode" (optional octal string applied at
// eof), "want_digest" (default true at eof).
//
// offset == 0 truncates first, so re-uploading over a LONGER existing file
// doesn't leave the old tail behind; the file is truncated again at eof to
// exactly offset+len(data) as a belt-and-braces guard for the case where a
// caller resumes an interrupted transfer at a non-zero offset over a file
// that was previously longer.
func (h *Handler) FsWriteChunk(ctx context.Context, args map[string]any) (map[string]any, error) {
	path, err := expandPath(stringArg(args, "path"))
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil, fmt.Errorf("write %s: is a directory", path)
	}

	data, err := base64.StdEncoding.DecodeString(stringArg(args, "data"))
	if err != nil {
		return nil, fmt.Errorf("decode chunk for %s: %w", path, err)
	}
	if len(data) > fsMaxChunk {
		return nil, fmt.Errorf("chunk of %d bytes exceeds the %d byte limit", len(data), fsMaxChunk)
	}

	offset := int64(floatArg(args, "offset", 0))
	if offset < 0 {
		return nil, fmt.Errorf("offset must not be negative")
	}
	eof := boolArg(args, "eof", false)

	if offset == 0 {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create parent of %s: %w", path, err)
		}
	}

	flags := os.O_WRONLY | os.O_CREATE
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s for write: %w", path, err)
	}

	if len(data) > 0 {
		if _, err := f.WriteAt(data, offset); err != nil {
			f.Close()
			return nil, fmt.Errorf("write %s at %d: %w", path, offset, err)
		}
	}
	end := offset + int64(len(data))
	if eof {
		if err := f.Truncate(end); err != nil {
			f.Close()
			return nil, fmt.Errorf("truncate %s to %d: %w", path, end, err)
		}
	}
	// Closed explicitly (not deferred) so a failed flush is reported as a
	// write failure — on a full disk the error surfaces here, not at WriteAt.
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close %s: %w", path, err)
	}

	out := map[string]any{
		"path": path, "offset": offset, "bytes": len(data), "eof": eof, "total": end,
	}
	if !eof {
		return out, nil
	}

	if mode := stringArg(args, "mode"); mode != "" {
		perm, err := parseFileMode(mode)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, perm); err != nil {
			return nil, fmt.Errorf("chmod %s: %w", path, err)
		}
	}
	if boolArg(args, "want_digest", true) {
		digest, skipped, err := fileDigest(path, end)
		if err != nil {
			return nil, err
		}
		if skipped {
			out["digest_skipped"] = true
		} else {
			out["sha256"] = digest
		}
	}
	return out, nil
}

// parseFileMode reads an octal permission string ("644", "0755").
func parseFileMode(mode string) (os.FileMode, error) {
	var perm uint32
	if _, err := fmt.Sscanf(strings.TrimPrefix(mode, "0o"), "%o", &perm); err != nil {
		return 0, fmt.Errorf("invalid mode %q: %w", mode, err)
	}
	if perm > 0o7777 {
		return 0, fmt.Errorf("invalid mode %q", mode)
	}
	return os.FileMode(perm), nil
}
