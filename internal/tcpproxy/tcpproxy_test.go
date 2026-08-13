package tcpproxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// echoServer stands up a real listener that upper-cases whatever it is sent.
// Real sockets on purpose: every failure mode in this package is socket
// plumbing, so a mocked net.Conn would only prove the mock agrees with itself.
func echoServer(t *testing.T) (host string, port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						up := make([]byte, n)
						for i := 0; i < n; i++ {
							b := buf[i]
							if b >= 'a' && b <= 'z' {
								b -= 32
							}
							up[i] = b
						}
						_, _ = c.Write(up)
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = ln.Close() }
}

func TestOpenRelaysBothDirections(t *testing.T) {
	host, port, stop := echoServer(t)
	defer stop()

	h := &Handler{}
	var mu sync.Mutex
	var got []byte
	done := make(chan struct{})

	err := h.OpenTCP(context.Background(), "s1", host, port,
		func(id string, data []byte) {
			mu.Lock()
			got = append(got, data...)
			if len(got) >= 5 {
				select {
				case <-done:
				default:
					close(done)
				}
			}
			mu.Unlock()
		},
		func(id, reason string) {},
	)
	if err != nil {
		t.Fatalf("OpenTCP: %v", err)
	}
	if err := h.SendTCP("s1", []byte("hello")); err != nil {
		t.Fatalf("SendTCP: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("no data relayed back within 3s")
	}
	mu.Lock()
	defer mu.Unlock()
	if string(got) != "HELLO" {
		t.Fatalf("relayed %q, want %q", got, "HELLO")
	}
}

func TestDialFailureIsReportedNotHung(t *testing.T) {
	// Bind then immediately release, so the port is almost certainly dead.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	h := &Handler{}
	err := h.OpenTCP(context.Background(), "s1", "127.0.0.1", port,
		func(string, []byte) {}, func(string, string) {})
	if err == nil {
		t.Fatal("expected a dial error; a silent hang is indistinguishable " +
			"from a quiet service and strands the consumer's socket")
	}
	if h.OpenCount() != 0 {
		t.Fatalf("a failed dial must not register a session, got %d", h.OpenCount())
	}
}

func TestRemoteCloseFiresEOFOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close() // hang up straight away
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)

	h := &Handler{}
	eof := make(chan string, 4)
	if err := h.OpenTCP(context.Background(), "s1", "127.0.0.1", addr.Port,
		func(string, []byte) {}, func(id, reason string) { eof <- reason }); err != nil {
		t.Fatalf("OpenTCP: %v", err)
	}

	select {
	case <-eof:
	case <-time.After(3 * time.Second):
		t.Fatal("remote close did not surface as EOF — the control plane " +
			"would wait for a timeout instead of tearing its half down")
	}
	select {
	case r := <-eof:
		t.Fatalf("EOF fired twice (second: %q)", r)
	case <-time.After(300 * time.Millisecond):
	}
	if h.OpenCount() != 0 {
		t.Fatalf("session should be forgotten after EOF, got %d", h.OpenCount())
	}
}

func TestSendToUnknownSessionErrors(t *testing.T) {
	h := &Handler{}
	if err := h.SendTCP("nope", []byte("x")); err == nil {
		t.Fatal("writing to an unknown session must error, not silently vanish")
	}
}

func TestCloseIsIdempotentAndCloseAllDrains(t *testing.T) {
	host, port, stop := echoServer(t)
	defer stop()

	h := &Handler{}
	for _, id := range []string{"a", "b", "c"} {
		if err := h.OpenTCP(context.Background(), id, host, port,
			func(string, []byte) {}, func(string, string) {}); err != nil {
			t.Fatalf("OpenTCP %s: %v", id, err)
		}
	}
	if h.OpenCount() != 3 {
		t.Fatalf("want 3 sessions, got %d", h.OpenCount())
	}
	if err := h.CloseTCP("a"); err != nil {
		t.Fatalf("CloseTCP: %v", err)
	}
	if err := h.CloseTCP("a"); err != nil {
		t.Fatalf("second CloseTCP must be a no-op, got %v", err)
	}
	h.CloseAllTCP()
	if h.OpenCount() != 0 {
		t.Fatalf("CloseAllTCP must drain every session, got %d", h.OpenCount())
	}
}

func TestInvalidTargetRejected(t *testing.T) {
	h := &Handler{}
	for _, tc := range []struct {
		host string
		port int
	}{{"", 5900}, {"h", 0}, {"h", 70000}, {"h", -1}} {
		if err := h.OpenTCP(context.Background(), "s", tc.host, tc.port,
			func(string, []byte) {}, func(string, string) {}); err == nil {
			t.Fatalf("expected rejection for %q:%d", tc.host, tc.port)
		}
	}
}

func TestReusedSessionIdClosesThePrevious(t *testing.T) {
	// Otherwise the first socket leaks with no id left to close it by.
	host, port, stop := echoServer(t)
	defer stop()

	h := &Handler{}
	for i := 0; i < 2; i++ {
		if err := h.OpenTCP(context.Background(), "same", host, port,
			func(string, []byte) {}, func(string, string) {}); err != nil {
			t.Fatalf("OpenTCP #%d: %v", i, err)
		}
	}
	if h.OpenCount() != 1 {
		t.Fatalf("a reused id must hold exactly one session, got %d", h.OpenCount())
	}
	h.CloseAllTCP()
}
