package sshobservation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestObserveConfirmsSSHAfterPreambleAndStopsBeforeKeyExchange(t *testing.T) {
	t.Parallel()

	serverBytes := []byte("maintenance notice\r\nSSH-2.0-OpenSSH_9.9 Ubuntu-1\r\n\x00\x00\x00\x0cKEX")
	conn := newMemoryConn(serverBytes, testPublicIPv4+":22")
	dialer := &recordingDialer{conn: conn}
	observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})

	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded || result.Evidence == nil {
		t.Fatalf("result = %#v, want succeeded evidence", result)
	}
	identification := result.Evidence.Identification
	if identification.Status != IdentificationReceived ||
		identification.ServerIdentification != "SSH-2.0-OpenSSH_9.9 Ubuntu-1" ||
		identification.ProtocolVersion != "2.0" ||
		identification.SoftwareVersion != "OpenSSH_9.9" ||
		identification.Comments != "Ubuntu-1" ||
		identification.PreambleLines != 1 ||
		!identification.ClientIdentificationSent {
		t.Fatalf("identification = %#v", identification)
	}
	if got := conn.written.String(); got != ClientIdentification+"\r\n" {
		t.Fatalf("client bytes = %q, want fixed identification", got)
	}
	if got := conn.remaining(); got != len("\x00\x00\x00\x0cKEX") {
		t.Fatalf("unread bytes = %d, want key exchange bytes untouched", got)
	}
	assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":22")
}

func TestObserveUsesCustomIPv6Endpoint(t *testing.T) {
	t.Parallel()

	conn := newMemoryConn([]byte("SSH-1.99-legacy_1.0\n"), "["+testPublicIPv6+"]:2222")
	dialer := &recordingDialer{conn: conn}
	observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv6, Port: 2222})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Input.Family != FamilyIPv6 || result.Evidence.Identification.ProtocolVersion != "1.99" {
		t.Fatalf("result = %#v, want IPv6 legacy-compatible identification", result)
	}
	assertSingleDial(t, dialer, "tcp6", "["+testPublicIPv6+"]:2222")
}

func TestObservePreservesReachableButUnconfirmedEvidence(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		serverBytes []byte
		readErr     error
		wantReason  UnconfirmedReason
		wantLines   int
	}{
		"invalid SSH line": {
			serverBytes: []byte("SSH-2.0-bad-software\r\n"),
			wantReason:  UnconfirmedInvalidIdentification,
		},
		"connection closed": {
			serverBytes: nil,
			wantReason:  UnconfirmedConnectionClosed,
		},
		"partial identification timeout": {
			serverBytes: []byte("SSH-2.0-Open"),
			readErr:     context.DeadlineExceeded,
			wantReason:  UnconfirmedTimeout,
		},
		"partial identification reset": {
			serverBytes: []byte("SSH-2.0-Open"),
			readErr:     syscall.ECONNRESET,
			wantReason:  UnconfirmedConnectionReset,
		},
		"preamble limit": {
			serverBytes: []byte(bytes.Repeat([]byte("notice\r\n"), maxPreambleLines+1)),
			wantReason:  UnconfirmedPreambleLimit,
			wantLines:   maxPreambleLines,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn := newMemoryConnWithReadError(test.serverBytes, testPublicIPv4+":22", test.readErr)
			dialer := &recordingDialer{conn: conn}
			observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})
			result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v; result = %#v", err, result)
			}
			identification := result.Evidence.Identification
			if result.Outcome != probe.OutcomeSucceeded ||
				identification.Status != IdentificationUnconfirmed ||
				identification.UnconfirmedReason != test.wantReason ||
				identification.PreambleLines != test.wantLines {
				t.Fatalf("result = %#v, want reachable/unconfirmed %q", result, test.wantReason)
			}
		})
	}
}

func TestObserveTCPFailureDurationIsOnlyConnectAttempt(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
	moments := []time.Time{
		start,
		start.Add(10 * time.Millisecond),
		start.Add(45 * time.Millisecond),
		start.Add(45 * time.Millisecond),
	}
	next := 0
	now := func() time.Time {
		if next >= len(moments) {
			t.Fatalf("clock called more than %d times", len(moments))
		}
		moment := moments[next]
		next++
		return moment
	}

	dialer := &recordingDialer{err: syscall.ECONNREFUSED}
	observer := mustTestObserver(t, Config{}, dependencies{now: now, dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
	assertFailure(t, result, probe.OutcomeFailed, FailureTCPConnectionRefused)
	if result.DurationMS != 35 {
		t.Fatalf("duration_ms = %d, want 35 ms TCP attempt", result.DurationMS)
	}
	if next != len(moments) {
		t.Fatalf("clock calls = %d, want %d", next, len(moments))
	}
}

func TestObserveIdentificationTimeoutKeepsTCPReachability(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer server.Close()
	remote := &reportedRemoteConn{Conn: client, remote: staticAddress(testPublicIPv4 + ":22")}
	dialer := &recordingDialer{conn: remote}
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		buffer := make([]byte, len(ClientIdentification)+2)
		_, _ = io.ReadFull(server, buffer)
		_, _ = server.Read(make([]byte, 1))
	}()

	observer := mustTestObserver(t, Config{Timeout: 20 * time.Millisecond}, dependencies{dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded ||
		result.Evidence.Identification.Status != IdentificationUnconfirmed ||
		result.Evidence.Identification.UnconfirmedReason != UnconfirmedTimeout ||
		!result.Evidence.Identification.ClientIdentificationSent {
		t.Fatalf("result = %#v, want reachable identification timeout", result)
	}
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("peer did not unblock after observation closed")
	}
}

func TestObserveClassifiesTCPFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		code probe.FailureCode
	}{
		"refused":  {err: syscall.ECONNREFUSED, code: FailureTCPConnectionRefused},
		"no route": {err: syscall.ENETUNREACH, code: FailureTCPNoRoute},
		"reset":    {err: syscall.ECONNRESET, code: FailureTCPConnectionReset},
		"other":    {err: errors.New("dial failed"), code: FailureTCP},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dialer := &recordingDialer{err: test.err}
			observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})
			result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
			assertFailure(t, result, probe.OutcomeFailed, test.code)
		})
	}
}

func TestObserveRejectsUnsafeTargetWithoutDial(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{err: errors.New("must not dial")}
	observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: "127.0.0.1"})
	assertFailure(t, result, probe.OutcomeFailed, probe.FailureInvalidInput)
	if calls := dialer.Calls(); len(calls) != 0 {
		t.Fatalf("dial calls = %#v, want none", calls)
	}
}

func TestObserveCancellationWinsAtSuccessCommit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	conn := newMemoryConn([]byte("SSH-2.0-OpenSSH_9.9\r\n"), testPublicIPv4+":22")
	dialer := &recordingDialer{conn: conn}
	observer := mustTestObserver(t, Config{}, dependencies{
		dialContext:         dialer.DialContext,
		beforeSuccessCommit: cancel,
	})
	result := observer.Observe(ctx, Request{DialIP: testPublicIPv4})
	assertFailure(t, result, probe.OutcomeCancelled, probe.FailureCancelled)
}

func mustTestObserver(t *testing.T, config Config, deps dependencies) *observer {
	t.Helper()
	observer, err := newObserver(config, deps)
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	return observer
}

func assertFailure(t *testing.T, result Result, outcome probe.Outcome, code probe.FailureCode) {
	t.Helper()
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != outcome || result.Failure == nil || result.Failure.Code != code {
		t.Fatalf("result outcome/failure = %q/%#v, want %q/%q", result.Outcome, result.Failure, outcome, code)
	}
}

type dialCall struct {
	network string
	address string
}

type recordingDialer struct {
	mu    sync.Mutex
	conn  net.Conn
	err   error
	calls []dialCall
}

func (d *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, dialCall{network: network, address: address})
	return d.conn, d.err
}

func (d *recordingDialer) Calls() []dialCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialCall(nil), d.calls...)
}

func assertSingleDial(t *testing.T, dialer *recordingDialer, network, address string) {
	t.Helper()
	calls := dialer.Calls()
	if len(calls) != 1 || calls[0] != (dialCall{network: network, address: address}) {
		t.Fatalf("dial calls = %#v, want one %s %s", calls, network, address)
	}
}

type memoryConn struct {
	mu      sync.Mutex
	reader  *bytes.Reader
	readErr error
	written bytes.Buffer
	remote  net.Addr
	closed  bool
}

func newMemoryConn(read []byte, remote string) *memoryConn {
	return newMemoryConnWithReadError(read, remote, nil)
}

func newMemoryConnWithReadError(read []byte, remote string, readErr error) *memoryConn {
	return &memoryConn{reader: bytes.NewReader(read), readErr: readErr, remote: staticAddress(remote)}
}

func (c *memoryConn) Read(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.reader.Read(data)
	if n == 0 && errors.Is(err, io.EOF) && c.readErr != nil {
		return 0, c.readErr
	}
	return n, err
}

func (c *memoryConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(data)
}

func (c *memoryConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *memoryConn) LocalAddr() net.Addr              { return staticAddress("127.0.0.1:1") }
func (c *memoryConn) RemoteAddr() net.Addr             { return c.remote }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }
func (c *memoryConn) remaining() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reader.Len()
}

type reportedRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *reportedRemoteConn) RemoteAddr() net.Addr { return c.remote }

type staticAddress string

func (a staticAddress) Network() string { return "tcp" }
func (a staticAddress) String() string  { return string(a) }
