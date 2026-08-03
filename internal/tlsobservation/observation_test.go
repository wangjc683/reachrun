package tlsobservation

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestObserveCompletesTLSWithoutSNIOrIdentityVerification(t *testing.T) {
	t.Parallel()

	serverNames := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("TLS-only observation must not send HTTP")
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverNames <- hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded || result.Evidence.TLS.Status != TLSCompleted {
		t.Fatalf("result = %#v, want completed TLS evidence", result)
	}
	if result.Input.SNIMode != SNIOmittedNoHostname ||
		result.Input.IdentityVerification != IdentityNotPerformedNoHostname {
		t.Fatalf("input = %#v, want explicit limited identity policy", result.Input)
	}
	if result.Evidence.RemoteEndpoint != testPublicIPv4+":443" ||
		result.Evidence.TLS.PeerCertificates < 1 ||
		result.Evidence.TLS.Leaf == nil ||
		len(result.Evidence.TLS.Leaf.SHA256) != 64 {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
	select {
	case serverName := <-serverNames:
		if serverName != "" {
			t.Fatalf("TLS SNI = %q, want omitted", serverName)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive ClientHello")
	}
	assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":443")
}

func TestObserveKeepsTCPReachabilityWhenTLSIsUnconfirmed(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded ||
		result.Evidence.TLS.Status != TLSUnconfirmed ||
		result.Evidence.TLS.UnconfirmedReason != UnconfirmedHandshakeFailure {
		t.Fatalf("result = %#v, want reachable/unconfirmed handshake", result)
	}
	assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":443")
}

func TestObserveTLSHandshakeTimeoutKeepsTCPReachability(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer server.Close()
	remote := &reportedRemoteConn{Conn: client, remote: staticAddress(testPublicIPv4 + ":443")}
	dialer := &recordingDialer{conn: remote}
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		_, _ = io.Copy(io.Discard, server)
	}()

	observer := mustTestObserver(t, Config{Timeout: 20 * time.Millisecond}, dependencies{dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv4})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded ||
		result.Evidence.TLS.Status != TLSUnconfirmed ||
		result.Evidence.TLS.UnconfirmedReason != UnconfirmedHandshakeTimeout {
		t.Fatalf("result = %#v, want TCP evidence plus TLS timeout", result)
	}
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("peer did not unblock after observation closed")
	}
}

func TestObserveUsesIPv6Endpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.StartTLS()
	defer server.Close()
	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{dialContext: dialer.DialContext})
	result := observer.Observe(context.Background(), Request{DialIP: testPublicIPv6})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Input.Family != FamilyIPv6 || result.Evidence.TLS.Status != TLSCompleted {
		t.Fatalf("result = %#v, want IPv6 completed evidence", result)
	}
	assertSingleDial(t, dialer, "tcp6", "["+testPublicIPv6+"]:443")
}

func TestObserveClassifiesTCPFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		code probe.FailureCode
	}{
		"refused":  {syscall.ECONNREFUSED, FailureTCPConnectionRefused},
		"no route": {syscall.ENETUNREACH, FailureTCPNoRoute},
		"reset":    {syscall.ECONNRESET, FailureTCPConnectionReset},
		"other":    {errors.New("dial failed"), FailureTCP},
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

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	dialer := newMappedDialer(server.Listener.Addr().String())
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

type mappedDialer struct {
	mapped string
	dialer net.Dialer
	mu     sync.Mutex
	calls  []dialCall
}

func newMappedDialer(mapped string) *mappedDialer {
	return &mappedDialer{mapped: mapped}
}

func (d *mappedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, dialCall{network: network, address: address})
	d.mu.Unlock()
	conn, err := d.dialer.DialContext(ctx, "tcp", d.mapped)
	if err != nil {
		return nil, err
	}
	return &reportedRemoteConn{Conn: conn, remote: staticAddress(address)}, nil
}

func (d *mappedDialer) Calls() []dialCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialCall(nil), d.calls...)
}

func assertSingleDial(t *testing.T, dialer interface{ Calls() []dialCall }, network, address string) {
	t.Helper()
	calls := dialer.Calls()
	if len(calls) != 1 || calls[0] != (dialCall{network: network, address: address}) {
		t.Fatalf("dial calls = %#v, want one %s %s", calls, network, address)
	}
}

type reportedRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *reportedRemoteConn) RemoteAddr() net.Addr { return c.remote }

type staticAddress string

func (a staticAddress) Network() string { return "tcp" }
func (a staticAddress) String() string  { return string(a) }
