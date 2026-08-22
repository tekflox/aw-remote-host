//go:build windows

// ConPTY — the Windows pseudoconsole, and the reason the interactive shell
// was unavailable on Windows hosts until now.
//
// creack/pty (used by the POSIX side) compiles for Windows but every entry
// point is a stub returning ErrUnsupported: its whole model is openpt/grantpt
// on a /dev/ptmx device, which has no Windows equivalent. Windows' answer,
// since Windows 10 1809, is ConPTY — you create a pseudoconsole object from
// a pair of pipes, hand it to a process through a process-thread ATTRIBUTE
// rather than through stdio handles, and the console host does the terminal
// emulation for you.
//
// That attribute is why os/exec cannot be used here the way it is on POSIX:
// exec.Cmd has no way to pass a PROC_THREAD_ATTRIBUTE_LIST, so this calls
// CreateProcess directly.
package shell

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procCreatePseudoConsole = kernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole = kernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole  = kernel32.NewProc("ClosePseudoConsole")
)

// procThreadAttributePseudoConsole is PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
// from processthreadsapi.h. Not exported by x/sys/windows, and it is a
// stable documented constant, so it is spelled out.
const procThreadAttributePseudoConsole = 0x00020016

// defaultCols/defaultRows are the size the pseudoconsole is created at.
// Manager.Open issues a Resize with the client's real size immediately
// afterwards; this is only what the shell sees for the few milliseconds
// before that lands.
const (
	defaultCols = 80
	defaultRows = 24
)

// coord packs a COORD (two SHORTs) into the single uintptr the Win32 ABI
// passes it as by value.
func coord(cols, rows uint16) uintptr {
	return uintptr(uint32(cols) | uint32(rows)<<16)
}

// handleAsAttributeValue reinterprets an HPCON's bits as the unsafe.Pointer
// that UpdateProcThreadAttribute's lpValue parameter expects.
//
// This looks like a hack and is instead the documented contract: lpValue is
// PVOID and *most* attributes point it at their data, but
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE is one of the exceptions where the
// handle is passed BY VALUE in that slot (Microsoft's own C sample passes
// `hPC` directly, with cbSize = sizeof(HPCON)). Pointing at the handle
// instead would hand the API the address of a local variable and the child
// would come up with no console.
//
// Written as a pointer-to-pointer reinterpretation rather than the obvious
// unsafe.Pointer(hpc) because that direct uintptr conversion is what
// `go vet`'s unsafeptr check exists to catch — and it is right to flag it in
// general. The value never participates in Go's pointer graph: it goes
// straight into a syscall and is not retained or dereferenced by Go.
func handleAsAttributeValue(h windows.Handle) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&h))
}

// conPTY is a live pseudoconsole plus the process attached to it.
type conPTY struct {
	hpc     windows.Handle
	in      *os.File // write end of the pseudoconsole's input pipe
	out     *os.File // read end of the pseudoconsole's output pipe
	proc    windows.Handle
	thread  windows.Handle
	closing sync.Once
}

func (c *conPTY) Read(p []byte) (int, error)  { return c.out.Read(p) }
func (c *conPTY) Write(p []byte) (int, error) { return c.in.Write(p) }

func (c *conPTY) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return nil // a zero dimension would blank the console
	}
	r, _, err := procResizePseudoConsole.Call(uintptr(c.hpc), coord(cols, rows))
	if r != 0 {
		return fmt.Errorf("ResizePseudoConsole(%dx%d): hresult=0x%x: %w", cols, rows, r, err)
	}
	return nil
}

// Close tears the session down. Order matters and is the fiddliest part of
// ConPTY: closing the INPUT pipe first gives the attached shell an EOF on
// stdin so it exits on its own, and only then does ClosePseudoConsole get
// called — the documented behaviour is that it waits for the client to
// finish reading pending output, so calling it while the shell is still
// happily waiting for input can block. TerminateProcess is the backstop for
// a shell that ignores its stdin closing.
func (c *conPTY) Close() error {
	c.closing.Do(func() {
		_ = c.in.Close()
		if c.proc != 0 {
			_ = windows.TerminateProcess(c.proc, 0)
		}
		if c.hpc != 0 {
			procClosePseudoConsole.Call(uintptr(c.hpc))
		}
		_ = c.out.Close()
		if c.thread != 0 {
			_ = windows.CloseHandle(c.thread)
		}
		if c.proc != 0 {
			_ = windows.CloseHandle(c.proc)
		}
	})
	return nil
}

// interactiveShellCommandLine is what a pty_open on a Windows host runs.
// pwsh when installed, powershell.exe otherwise — the same preference (and
// the same reason: 5.1 is drastically slower to start) as the non-interactive
// path in internal/ops/proc_windows.go.
//
// -NoLogo suppresses the copyright banner that would otherwise be the first
// thing in every session. -NoExit is NOT wanted: without a -Command this is
// already an interactive REPL.
func interactiveShellCommandLine() string {
	if path, err := exec.LookPath("pwsh.exe"); err == nil && path != "" {
		return `pwsh.exe -NoLogo`
	}
	return `powershell.exe -NoLogo`
}

// startConPTY creates a pseudoconsole and starts commandLine attached to it.
func startConPTY(commandLine string) (_ PTY, err error) {
	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("create conpty input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		return nil, fmt.Errorf("create conpty output pipe: %w", err)
	}

	var hpc windows.Handle
	// Returns an HRESULT, not a BOOL — 0 (S_OK) is success, and the
	// GetLastError value the Call helper hands back is meaningless here.
	r, _, _ := procCreatePseudoConsole.Call(
		coord(defaultCols, defaultRows),
		uintptr(inRead), uintptr(outWrite),
		0,
		uintptr(unsafe.Pointer(&hpc)),
	)
	// The pseudoconsole duplicates what it needs; these two ends belong to
	// it now and MUST be closed here. Leaving them open is the classic
	// ConPTY leak — the output pipe never reaches EOF, so a reader on the
	// other end hangs forever after the shell exits.
	_ = windows.CloseHandle(inRead)
	_ = windows.CloseHandle(outWrite)
	if r != 0 {
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		return nil, fmt.Errorf("CreatePseudoConsole: hresult=0x%x "+
			"(ConPTY needs Windows 10 1809 or newer)", r)
	}

	defer func() {
		if err != nil {
			procClosePseudoConsole.Call(uintptr(hpc))
			_ = windows.CloseHandle(inWrite)
			_ = windows.CloseHandle(outRead)
		}
	}()

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, fmt.Errorf("alloc proc thread attribute list: %w", err)
	}
	defer attrs.Delete()

	if err := attrs.Update(
		procThreadAttributePseudoConsole,
		handleAsAttributeValue(hpc),
		unsafe.Sizeof(hpc),
	); err != nil {
		return nil, fmt.Errorf("attach pseudoconsole to process attributes: %w", err)
	}

	si := new(windows.StartupInfoEx)
	si.ProcThreadAttributeList = attrs.List()
	si.Cb = uint32(unsafe.Sizeof(*si))
	// Deliberately NOT setting STARTF_USESTDHANDLES: with a pseudoconsole
	// attached, the console host supplies the child's stdio. Setting it here
	// makes CreateProcess prefer the (unset) handle fields and the child
	// comes up with no usable terminal at all.

	cmdline, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return nil, fmt.Errorf("encode command line %q: %w", commandLine, err)
	}

	var pi windows.ProcessInformation
	if err := windows.CreateProcess(
		nil, cmdline,
		nil, nil,
		false, // handle inheritance off — the pseudoconsole is the channel
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		nil, nil,
		&si.StartupInfo, &pi,
	); err != nil {
		return nil, fmt.Errorf("start %q under pseudoconsole: %w", commandLine, err)
	}

	return &conPTY{
		hpc:    hpc,
		in:     os.NewFile(uintptr(inWrite), "conpty-in"),
		out:    os.NewFile(uintptr(outRead), "conpty-out"),
		proc:   pi.Process,
		thread: pi.Thread,
	}, nil
}

// startPTY is the Windows half of DefaultSpawner — see spawn_unix.go for the
// POSIX twin.
//
// TargetWorkspace is refused rather than attempted: it means `podman exec`
// into the workspace container, and a Windows host has no workspace (the
// image is a Linux container — see internal/ops.workspaceRuntimeSupported).
// Letting it through would surface as "podman: not found", which reads like
// a broken PATH instead of a target that cannot exist here.
func startPTY(_ context.Context, resolved string) (PTY, error) {
	if resolved == TargetWorkspace {
		return nil, fmt.Errorf(
			"no workspace container on a Windows host to open a shell in — "+
				"this host is linked lean; use target %q for a shell on the machine itself", TargetHost)
	}
	return startConPTY(interactiveShellCommandLine())
}
