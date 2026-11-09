package ops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// update_preflight is read-only and must never take the per-machine
// lifecycle lock Dispatch holds for update/reinstall/bootstrap — a preview
// that waited behind a real in-flight update would defeat the point of a
// cheap preflight the confirmation modal calls before every click.
func TestUpdatePreflightIsLifecycleGatedButNeverLockTaking(t *testing.T) {
	if !workspaceLifecycleVerbs["update_preflight"] {
		t.Fatal("update_preflight must be in workspaceLifecycleVerbs — a lean host with no local runtime must refuse it with the same clear message as update")
	}
	if workspaceRecreateVerbs["update_preflight"] {
		t.Fatal("update_preflight must NOT be in workspaceRecreateVerbs — it writes nothing and must not wait on, or hold, the per-machine lifecycle lock")
	}
}

func TestDispatchRoutesToUpdatePreflight(t *testing.T) {
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := newFakeRunner()
	h := &Handler{Runner: r}

	data, err := h.Dispatch(context.Background(), "update_preflight", nil, nil)
	if err != nil {
		t.Fatalf("Dispatch(update_preflight): %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("expected a map result, got %T", data)
	}
	if m["git_checkout"] != false {
		t.Fatalf("a plain temp dir with no .git is not a checkout: %v", m)
	}
}

// The core promise of the preview: the exact dirty-file list a force-update
// modal needs, without parsing the guard's own truncated error string.
func TestUpdatePreflightReportsDirtyFilesAndShortstat(t *testing.T) {
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := newFakeRunner()
	r.on("hostsha123\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "rev-parse", "HEAD")
	r.on(" M src/apps/reconciler.py\n D old/file.txt\n?? .tmp/scratch\n",
		"git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")
	r.on(" 2 files changed, 10 insertions(+), 3 deletions(-)\n",
		"git", "-c", "safe.directory="+hostDir, "-C", hostDir, "diff", "HEAD", "--shortstat")

	h := &Handler{Runner: r}
	result, err := h.UpdatePreflight(context.Background(), nil)
	if err != nil {
		t.Fatalf("UpdatePreflight: %v", err)
	}
	if result["git_checkout"] != true || result["head"] != "hostsha123" {
		t.Fatalf("expected a resolved checkout, got %v", result)
	}
	if result["dirty_count"] != 2 {
		t.Fatalf("untracked files must not count as dirty, got dirty_count=%v", result["dirty_count"])
	}
	dirty, ok := result["dirty"].([]map[string]string)
	if !ok || len(dirty) != 2 {
		t.Fatalf("expected 2 structured dirty entries, got %v", result["dirty"])
	}
	if dirty[0]["status"] != "M" || dirty[0]["path"] != "src/apps/reconciler.py" {
		t.Errorf("unexpected first entry: %v", dirty[0])
	}
	if dirty[1]["status"] != "D" || dirty[1]["path"] != "old/file.txt" {
		t.Errorf("unexpected second entry: %v", dirty[1])
	}
	if result["truncated"] != false {
		t.Errorf("2 entries must not be reported as truncated: %v", result["truncated"])
	}
	if !strings.Contains(fmt.Sprint(result["shortstat"]), "2 files changed") {
		t.Errorf("expected the shortstat in the result, got %v", result["shortstat"])
	}
}

// A clean tree must report dirty_count=0 and must not even bother asking
// for a shortstat — there is nothing to summarize.
func TestUpdatePreflightCleanTreeReportsNoDirtyFiles(t *testing.T) {
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := newFakeRunner()
	r.on("hostsha123\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "rev-parse", "HEAD")
	r.on("\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")

	h := &Handler{Runner: r}
	result, err := h.UpdatePreflight(context.Background(), nil)
	if err != nil {
		t.Fatalf("UpdatePreflight: %v", err)
	}
	if result["dirty_count"] != 0 {
		t.Fatalf("expected dirty_count=0, got %v", result["dirty_count"])
	}
	if r.ran("shortstat") {
		t.Error("must not query a shortstat for a clean tree")
	}
}

// A host with no git checkout (or no git at all) must preview as "nothing
// to tell" rather than error — the modal that calls this falls back to the
// pre-preflight error-string behavior on any failure, and an error here
// would make every force-update modal degrade on a perfectly normal host.
func TestUpdatePreflightNotACheckoutIsSilent(t *testing.T) {
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := newFakeRunner()
	r.fail(fmt.Errorf("fatal: not a git repository"),
		"git", "-c", "safe.directory="+hostDir, "-C", hostDir, "rev-parse", "HEAD")

	h := &Handler{Runner: r}
	result, err := h.UpdatePreflight(context.Background(), nil)
	if err != nil {
		t.Fatalf("UpdatePreflight must not error on a non-checkout host: %v", err)
	}
	if result["git_checkout"] != false {
		t.Fatalf("expected git_checkout=false, got %v", result)
	}
	if _, ok := result["dirty"]; ok {
		t.Errorf("must not report a dirty list when there is no checkout: %v", result)
	}
}

// Same ahead-of-image semantics as guardHostNotAheadOfImage: a tag that
// resolves to the host's own commit means "no", not "unknown".
func TestUpdatePreflightAheadNoWhenHostMatchesImage(t *testing.T) {
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := newFakeRunner()
	r.on("hostsha123\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "rev-parse", "HEAD")
	r.on("\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")
	r.on("AW_WORKSPACE_VERSION=hostsha123", "podman", "image", "inspect",
		WorkspaceImage, "--format", "{{range .Config.Env}}{{println .}}{{end}}")
	r.on("hostsha123", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "rev-parse", "hostsha123^{commit}")

	h := &Handler{Runner: r}
	result, err := h.UpdatePreflight(context.Background(), nil)
	if err != nil {
		t.Fatalf("UpdatePreflight: %v", err)
	}
	if result["ahead"] != "no" {
		t.Fatalf("expected ahead=no when host and image resolve to the same commit, got %v", result["ahead"])
	}
}

// And a provable ancestor relationship must report "yes", mirroring the
// guard's own refusal case exactly (TestUpdateRefusesWhenHostHeadIsAheadOfImage).
func TestUpdatePreflightAheadYesWhenHostIsProvablyAheadOfImage(t *testing.T) {
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := newFakeRunner()
	r.on("hostsha123\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "rev-parse", "HEAD")
	r.on("\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")
	r.on("AW_WORKSPACE_VERSION=imagesha456", "podman", "image", "inspect",
		WorkspaceImage, "--format", "{{range .Config.Env}}{{println .}}{{end}}")
	r.on("", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "merge-base", "--is-ancestor", "imagesha456", "hostsha123")

	h := &Handler{Runner: r}
	result, err := h.UpdatePreflight(context.Background(), nil)
	if err != nil {
		t.Fatalf("UpdatePreflight: %v", err)
	}
	if result["ahead"] != "yes" {
		t.Fatalf("expected ahead=yes, got %v", result["ahead"])
	}
}

// The cap exists so an UpdatePreflight response can never grow unbounded on
// a wildly diverged host — but the caller still needs the real total, not
// just the capped list.
func TestUpdatePreflightCapsListButReportsTrueCount(t *testing.T) {
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	var porcelain strings.Builder
	for i := 0; i < 1001; i++ {
		fmt.Fprintf(&porcelain, " M file%d.txt\n", i)
	}

	r := newFakeRunner()
	r.on("hostsha123\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "rev-parse", "HEAD")
	r.on(porcelain.String(), "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")
	r.on("1001 files changed\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "diff", "HEAD", "--shortstat")

	h := &Handler{Runner: r}
	result, err := h.UpdatePreflight(context.Background(), nil)
	if err != nil {
		t.Fatalf("UpdatePreflight: %v", err)
	}
	if result["dirty_count"] != 1001 {
		t.Fatalf("dirty_count must be the TRUE total, got %v", result["dirty_count"])
	}
	dirty, _ := result["dirty"].([]map[string]string)
	if len(dirty) != 1000 {
		t.Fatalf("expected the list capped at 1000, got %d", len(dirty))
	}
	if result["truncated"] != true {
		t.Fatalf("expected truncated=true, got %v", result["truncated"])
	}
}

// Direct coverage of the helper preview and guard now both depend on — the
// one the design calls OBRIGATÓRIO: a preview and a guard that parse
// porcelain output differently is how a modal shows 0 files while the guard
// still refuses, or the reverse.
func TestParseHostDirtyEntriesExcludesUntrackedAndIgnored(t *testing.T) {
	out := " M src/apps/reconciler.py\n?? .tmp/scratch\n!! node_modules/\nD  removed.txt\n"
	entries := parseHostDirtyEntries(out)
	if len(entries) != 2 {
		t.Fatalf("expected 2 tracked entries, got %d: %v", len(entries), entries)
	}
	if entries[0].Status != "M" || entries[0].Path != "src/apps/reconciler.py" {
		t.Errorf("unexpected entry 0: %+v", entries[0])
	}
	if entries[1].Status != "D" || entries[1].Path != "removed.txt" {
		t.Errorf("unexpected entry 1: %+v", entries[1])
	}
}

// --- force-update backup (Handler.Update, force=true path) ---

// The central promise of the fail-closed design: a force update over a
// dirty tree must write a recoverable backup BEFORE the sync destroys
// anything, and the result must say what it discarded and where it went.
func TestForceUpdateBacksUpDirtyFilesBeforeDiscardingThem(t *testing.T) {
	stubRunModule(t)
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	// A real on-disk file for the modified entry — backupDirtyHostState only
	// tars paths that still exist, and this proves it finds them.
	if err := os.MkdirAll(filepath.Join(hostDir, "src", "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "src", "apps", "reconciler.py"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &copyingRunner{fakeRunner: newFakeRunner()}
	r.on(" M src/apps/reconciler.py\n D old/file.txt\n",
		"git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")

	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	data, err := h.Update(context.Background(), h.Opts, map[string]any{"force": true}, emit)
	if err != nil {
		t.Fatalf("Update with force=true over a dirty tree: %v", err)
	}

	if data["forced"] != true {
		t.Errorf("expected forced=true in the result, got %v", data)
	}
	discarded, _ := data["discarded_files"].([]string)
	if len(discarded) != 2 {
		t.Fatalf("expected 2 discarded_files, got %v", data["discarded_files"])
	}
	backupDir, _ := data["backup_dir"].(string)
	if backupDir == "" {
		t.Fatal("expected a non-empty backup_dir in the result")
	}
	wantRoot := filepath.Join(hostDir, ".aw-workspace", "update-backups")
	if !strings.HasPrefix(backupDir, wantRoot) {
		t.Fatalf("backup_dir %q must live under %q (syncWorkspaceSource excludes .aw-workspace)", backupDir, wantRoot)
	}

	for _, name := range []string{"status.txt", "HEAD.txt", "dirty.patch"} {
		if _, err := os.Stat(filepath.Join(backupDir, name)); err != nil {
			t.Errorf("expected backup artifact %s to exist: %v", name, err)
		}
	}

	var tarCall []string
	var cpCall []string
	for i, call := range r.calls {
		if len(call) > 0 && call[0] == "tar" {
			tarCall = call
		}
		if len(call) >= 2 && call[0] == "podman" && call[1] == "cp" && cpCall == nil {
			cpCall = call
			_ = i
		}
	}
	if tarCall == nil {
		t.Fatal("expected a tar call to back up the surviving dirty file")
	}
	joinedTar := strings.Join(tarCall, " ")
	if !strings.Contains(joinedTar, "src/apps/reconciler.py") {
		t.Errorf("tar call should include the surviving modified file: %v", tarCall)
	}
	if strings.Contains(joinedTar, "old/file.txt") {
		t.Errorf("tar call must exclude the deleted file — it has nothing left on disk to tar: %v", tarCall)
	}

	tarIdx, cpIdx := -1, -1
	for i, call := range r.calls {
		if len(call) > 0 && call[0] == "tar" {
			tarIdx = i
		}
		if cpIdx == -1 && len(call) >= 2 && call[0] == "podman" && call[1] == "cp" {
			cpIdx = i
		}
	}
	if tarIdx == -1 || cpIdx == -1 || tarIdx > cpIdx {
		t.Fatalf("the backup must be written BEFORE the image source is staged/synced, tarIdx=%d cpIdx=%d", tarIdx, cpIdx)
	}

	joined := strings.Join(*lines, " ")
	if !strings.Contains(joined, "backed up 2 uncommitted file(s)") {
		t.Errorf("expected the backup to be logged, got: %s", joined)
	}
}

// force=true over an already-clean tree must not fabricate a backup — there
// is nothing to discard, so no backup dir, no discarded_files.
func TestForceUpdateWithCleanTreeSkipsBackupEntirely(t *testing.T) {
	stubRunModule(t)
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := &copyingRunner{fakeRunner: newFakeRunner()}
	r.on("\n", "git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")

	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, _ := collectEmits()

	data, err := h.Update(context.Background(), h.Opts, map[string]any{"force": true}, emit)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if data["forced"] != true {
		t.Errorf("forced must still be true, got %v", data)
	}
	if _, ok := data["backup_dir"]; ok {
		t.Errorf("must not report a backup_dir when nothing was dirty: %v", data)
	}
	if r.ran("tar") {
		t.Error("must not have run tar when there was nothing to back up")
	}
	if _, err := os.Stat(filepath.Join(hostDir, ".aw-workspace", "update-backups")); err == nil {
		t.Error("must not even create the update-backups directory when there is nothing dirty")
	}
}

// FAIL-CLOSED: if the backup cannot be captured (disk full, a git failure —
// modeled here as the diff command itself failing), Update must refuse to
// proceed rather than silently discard uncommitted work with no safety net.
// The UI promises a recoverable backup before the user checks the box; a
// backup that silently failed would make that promise a lie.
func TestForceUpdateFailsClosedWhenBackupCannotBeCaptured(t *testing.T) {
	stubRunModule(t)
	useTempState(t)
	hostDir := t.TempDir()
	t.Setenv("AW_WORKSPACE_HOST_DIR", hostDir)

	r := &copyingRunner{fakeRunner: newFakeRunner()}
	r.on(" M src/apps/reconciler.py\n",
		"git", "-c", "safe.directory="+hostDir, "-C", hostDir, "status", "--porcelain")
	r.fail(fmt.Errorf("no space left on device"),
		"git", "-c", "safe.directory="+hostDir, "-C", hostDir, "diff", "HEAD", "--binary")

	h := &Handler{Runner: r, Opts: BootstrapOpts{ExtractDir: t.TempDir()}}
	emit, lines := collectEmits()

	_, err := h.Update(context.Background(), h.Opts, map[string]any{"force": true}, emit)
	if err == nil {
		t.Fatal("expected Update to refuse when the backup cannot be captured")
	}
	for _, call := range r.calls {
		if len(call) >= 2 && call[0] == "podman" && call[1] == "cp" {
			t.Fatalf("must not have staged/synced anything once the backup failed, calls=%v", r.calls)
		}
	}
	joined := strings.Join(*lines, " ")
	if !strings.Contains(joined, "backup failed") {
		t.Errorf("expected a loud error naming the backup failure, got: %s", joined)
	}
}

// --- pruneOldUpdateBackups ---

func TestPruneOldUpdateBackupsKeepsOnlyTheFiveMostRecent(t *testing.T) {
	root := t.TempDir()
	var names []string
	base := int64(1700000000000000000)
	for i := 0; i < 7; i++ {
		name := fmt.Sprintf("%d-v0.1.%d", base+int64(i), i)
		names = append(names, name)
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	h := &Handler{Runner: newFakeRunner()}
	if err := h.pruneOldUpdateBackups(context.Background(), root, ""); err != nil {
		t.Fatalf("pruneOldUpdateBackups: %v", err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected exactly 5 backups to survive, got %d: %v", len(entries), entries)
	}
	for _, oldName := range names[:2] {
		if _, err := os.Stat(filepath.Join(root, oldName)); err == nil {
			t.Errorf("expected the oldest backup %s to be pruned", oldName)
		}
	}
	for _, newName := range names[2:] {
		if _, err := os.Stat(filepath.Join(root, newName)); err != nil {
			t.Errorf("expected the recent backup %s to survive: %v", newName, err)
		}
	}
}

// The backup just written must never be pruned by its own prune call, even
// if an unlucky clock or naming collision would otherwise put it first in
// line — pruneOldUpdateBackups is called from inside the very function that
// just created this directory.
func TestPruneOldUpdateBackupsNeverRemovesTheOneJustWritten(t *testing.T) {
	root := t.TempDir()
	base := int64(1600000000000000000) // deliberately the OLDEST-sorting name
	justWritten := fmt.Sprintf("%d-v0.1.0", base)
	if err := os.MkdirAll(filepath.Join(root, justWritten), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("%d-v0.1.%d", int64(1700000000000000000)+int64(i), i)
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	h := &Handler{Runner: newFakeRunner()}
	if err := h.pruneOldUpdateBackups(context.Background(), root, filepath.Join(root, justWritten)); err != nil {
		t.Fatalf("pruneOldUpdateBackups: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, justWritten)); err != nil {
		t.Fatalf("must never remove the backup just written, even though it sorts oldest: %v", err)
	}
}
