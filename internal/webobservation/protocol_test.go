package webobservation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	testPublicIPv4 = "93.184.216.34"
	testPublicIPv6 = "2606:4700:4700::1111"
)

func TestObserveHTTPSUsesLiteralIPHostSNIAndCertificate(t *testing.T) {
	t.Parallel()

	requests := make(chan requestFacts, 1)
	serverNames := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- requestFacts{
			host:          request.Host,
			method:        request.Method,
			path:          request.URL.Path,
			authorization: request.Header.Get("Authorization"),
			cookie:        request.Header.Get("Cookie"),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverNames <- hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(server.Certificate())
	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{
		now:         time.Now,
		dialContext: dialer.DialContext,
		rootCAs:     rootCAs,
	})

	result := observer.Observe(context.Background(), Request{
		Scheme:   SchemeHTTPS,
		Hostname: "EXAMPLE.COM.",
		DialIP:   testPublicIPv4,
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		t.Fatalf("Outcome = %q, want succeeded; failure = %#v", result.Outcome, result.Failure)
	}
	if result.Input.Hostname != "example.com" || result.Input.Family != FamilyIPv4 {
		t.Fatalf("Input = %#v, want normalized hostname and IPv4", result.Input)
	}
	if result.Evidence.RemoteEndpoint != testPublicIPv4+":443" {
		t.Fatalf("RemoteEndpoint = %q", result.Evidence.RemoteEndpoint)
	}
	if result.Evidence.TLS == nil {
		t.Fatal("TLS evidence = nil")
	}
	if result.Evidence.TLS.ServerName != "example.com" ||
		result.Evidence.TLS.VerifiedChains < 1 ||
		len(result.Evidence.TLS.Leaf.SHA256) != 64 {
		t.Fatalf("TLS evidence = %#v", result.Evidence.TLS)
	}
	if result.Evidence.HTTP.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d", result.Evidence.HTTP.StatusCode)
	}

	assertRequestFacts(t, requests, requestFacts{
		host:   "example.com",
		method: http.MethodGet,
		path:   "/",
	})
	assertChannelValue(t, serverNames, "example.com", "TLS SNI")
	assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":443")
}

func TestObserveIPv6UsesTCP6AndKeepsFamilySeparate(t *testing.T) {
	t.Parallel()

	hosts := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		hosts <- request.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{
		now:         time.Now,
		dialContext: dialer.DialContext,
	})
	result := observer.Observe(context.Background(), Request{
		Scheme:   SchemeHTTP,
		Hostname: "ipv6.example",
		DialIP:   testPublicIPv6,
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Input.Family != FamilyIPv6 || result.Input.DialIP != testPublicIPv6 {
		t.Fatalf("Input = %#v, want one IPv6 candidate", result.Input)
	}
	if result.Evidence.TLS != nil {
		t.Fatalf("plain HTTP evidence includes TLS: %#v", result.Evidence.TLS)
	}
	assertChannelValue(t, hosts, "ipv6.example", "HTTP Host")
	assertSingleDial(t, dialer, "tcp6", "["+testPublicIPv6+"]:80")
}

func TestObserveRedirectIsEvidenceWithoutASecondDial(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://next.example/path")
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{
		now:         time.Now,
		dialContext: dialer.DialContext,
	})
	result := observer.Observe(context.Background(), Request{
		Scheme:   SchemeHTTP,
		Hostname: "redirect.example",
		DialIP:   testPublicIPv4,
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Evidence.HTTP.StatusCode != http.StatusFound ||
		result.Evidence.HTTP.Location != "https://next.example/path" ||
		result.Evidence.HTTP.RetryAfter != "120" {
		t.Fatalf("HTTP evidence = %#v", result.Evidence.HTTP)
	}
	assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":80")
}

func TestObserveOmitsOversizedOptionalHeadersWithoutLosingHTTPStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", strings.Repeat("x", maxLocationBytes+1))
		w.Header().Set("Retry-After", strings.Repeat("1", maxRetryAfterBytes+1))
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{
		now:         time.Now,
		dialContext: dialer.DialContext,
	})
	result := observer.Observe(context.Background(), Request{
		Scheme:   SchemeHTTP,
		Hostname: "redirect.example",
		DialIP:   testPublicIPv4,
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded ||
		result.Evidence.HTTP.StatusCode != http.StatusFound ||
		!result.Evidence.HTTP.LocationOmitted ||
		!result.Evidence.HTTP.RetryAfterOmitted ||
		result.Evidence.HTTP.Location != "" ||
		result.Evidence.HTTP.RetryAfter != "" {
		t.Fatalf("HTTP evidence = %#v, want successful status with omitted metadata", result.Evidence.HTTP)
	}
	assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":80")
}

func TestObserveHTTPErrorStatusesAreSuccessfulEvidence(t *testing.T) {
	t.Parallel()

	for _, status := range []int{
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	} {
		status := status
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			dialer := newMappedDialer(server.Listener.Addr().String())
			observer := mustTestObserver(t, Config{}, dependencies{
				now:         time.Now,
				dialContext: dialer.DialContext,
			})
			result := observer.Observe(context.Background(), Request{
				Scheme:   SchemeHTTP,
				Hostname: "status.example",
				DialIP:   testPublicIPv4,
			})
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v; result = %#v", err, result)
			}
			if result.Outcome != probe.OutcomeSucceeded || result.Evidence.HTTP.StatusCode != status {
				t.Fatalf("result = %#v, want succeeded HTTP %d evidence", result, status)
			}
			assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":80")
		})
	}
}

func TestObserveRejectsCertificateForAnotherHostname(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(server.Certificate())
	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{
		now:         time.Now,
		dialContext: dialer.DialContext,
		rootCAs:     rootCAs,
	})
	result := observer.Observe(context.Background(), Request{
		Scheme:   SchemeHTTPS,
		Hostname: "wrong.invalid",
		DialIP:   testPublicIPv4,
	})
	assertFailure(t, result, probe.OutcomeFailed, FailureTLSCertificate)
	assertSingleDial(t, dialer, "tcp4", testPublicIPv4+":443")
}

func TestObserveTimeoutIsClassifiedAtTCPStage(t *testing.T) {
	t.Parallel()

	observer := mustTestObserver(t, Config{Timeout: 10 * time.Millisecond}, dependencies{
		now: time.Now,
		dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	result := observer.Observe(context.Background(), Request{
		Scheme:   SchemeHTTPS,
		Hostname: "timeout.example",
		DialIP:   testPublicIPv4,
	})
	assertFailure(t, result, probe.OutcomeFailed, FailureTCPTimeout)
}

func TestObserveCancellationWinsAtSuccessCommit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	dialer := newMappedDialer(server.Listener.Addr().String())
	observer := mustTestObserver(t, Config{}, dependencies{
		now:                 time.Now,
		dialContext:         dialer.DialContext,
		beforeSuccessCommit: cancel,
	})
	result := observer.Observe(ctx, Request{
		Scheme:   SchemeHTTP,
		Hostname: "cancel.example",
		DialIP:   testPublicIPv4,
	})
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

func assertFailure(
	t *testing.T,
	result Result,
	wantOutcome probe.Outcome,
	wantCode probe.FailureCode,
) {
	t.Helper()
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != wantOutcome || result.Failure == nil || result.Failure.Code != wantCode {
		t.Fatalf(
			"result outcome/failure = %q/%#v, want %q/%q",
			result.Outcome,
			result.Failure,
			wantOutcome,
			wantCode,
		)
	}
}

func assertChannelValue(t *testing.T, values <-chan string, want, label string) {
	t.Helper()
	select {
	case got := <-values:
		if got != want {
			t.Fatalf("%s = %q, want %q", label, got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

type dialCall struct {
	network string
	address string
}

type requestFacts struct {
	host          string
	method        string
	path          string
	authorization string
	cookie        string
}

func assertRequestFacts(t *testing.T, requests <-chan requestFacts, want requestFacts) {
	t.Helper()
	select {
	case got := <-requests:
		if got != want {
			t.Fatalf("HTTP request facts = %#v, want %#v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP request")
	}
}

type mappedDialer struct {
	serverAddress string

	mu    sync.Mutex
	calls []dialCall
}

func newMappedDialer(serverAddress string) *mappedDialer {
	return &mappedDialer{serverAddress: serverAddress}
}

func (d *mappedDialer) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, dialCall{network: network, address: address})
	d.mu.Unlock()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.serverAddress)
	if err != nil {
		return nil, err
	}
	return &reportedRemoteConn{
		Conn:   conn,
		remote: staticAddress(address),
	}, nil
}

func (d *mappedDialer) Calls() []dialCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialCall(nil), d.calls...)
}

type reportedRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *reportedRemoteConn) RemoteAddr() net.Addr {
	return c.remote
}

type staticAddress string

func (a staticAddress) Network() string { return "tcp" }
func (a staticAddress) String() string  { return string(a) }

func assertSingleDial(t *testing.T, dialer *mappedDialer, network, address string) {
	t.Helper()
	calls := dialer.Calls()
	if len(calls) != 1 || calls[0].network != network || calls[0].address != address {
		t.Fatalf("dial calls = %#v, want one %s %s", calls, network, address)
	}
}
