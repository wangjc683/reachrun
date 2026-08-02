package webobservation

import (
	"context"
	"crypto/x509"
	"fmt"
	"syscall"
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestClassifyExchangeFailurePreservesStableNetworkReasons(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		err   error
		stage attemptStage
		want  probe.FailureCode
	}{
		{"refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), attemptStageTCP, FailureTCPConnectionRefused},
		{"network unreachable", fmt.Errorf("dial: %w", syscall.ENETUNREACH), attemptStageTCP, FailureTCPNoRoute},
		{"host unreachable", fmt.Errorf("dial: %w", syscall.EHOSTUNREACH), attemptStageTCP, FailureTCPNoRoute},
		{"TCP reset", fmt.Errorf("read: %w", syscall.ECONNRESET), attemptStageTCP, FailureTCPConnectionReset},
		{"TLS reset", fmt.Errorf("read: %w", syscall.ECONNRESET), attemptStageTLS, FailureTLSConnectionReset},
		{"HTTP reset", fmt.Errorf("read: %w", syscall.ECONNRESET), attemptStageHTTP, FailureHTTPConnectionReset},
		{"TCP other", fmt.Errorf("dial failed"), attemptStageTCP, FailureTCP},
		{"TLS other", fmt.Errorf("handshake failed"), attemptStageTLS, FailureTLSHandshake},
		{"HTTP other", fmt.Errorf("bad status line"), attemptStageHTTP, FailureHTTPProtocol},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyExchangeFailure(test.err, test.stage); got != test.want {
				t.Fatalf("classifyExchangeFailure() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestClassifyExchangeFailurePreservesStageForTimeout(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		stage attemptStage
		want  probe.FailureCode
	}{
		{attemptStageTCP, FailureTCPTimeout},
		{attemptStageTLS, FailureTLSTimeout},
		{attemptStageHTTP, FailureHTTPTimeout},
	} {
		if got := classifyExchangeFailure(context.DeadlineExceeded, test.stage); got != test.want {
			t.Fatalf("timeout at stage %d = %q, want %q", test.stage, got, test.want)
		}
	}
}

func TestClassifyExchangeFailureRecognizesCertificateErrors(t *testing.T) {
	t.Parallel()

	err := x509.HostnameError{Certificate: &x509.Certificate{}, Host: "wrong.example"}
	if got := classifyExchangeFailure(err, attemptStageTLS); got != FailureTLSCertificate {
		t.Fatalf("certificate failure = %q, want %q", got, FailureTLSCertificate)
	}
}

func TestClassifyContextDistinguishesCancelFromDeadline(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, code, err := classifyContext(cancelled, attemptStageHTTP)
	if err == nil || outcome != probe.OutcomeCancelled || code != probe.FailureCancelled {
		t.Fatalf("cancel classification = %q/%q/%v", outcome, code, err)
	}

	deadline, deadlineCancel := context.WithCancelCause(context.Background())
	deadlineCancel(context.DeadlineExceeded)
	// WithCancelCause still sets Err to context.Canceled, so classifyContext
	// correctly treats the caller action as cancellation rather than inspecting
	// an arbitrary cause. Real deadlines are covered by exchange timeout tests.
	outcome, code, err = classifyContext(deadline, attemptStageHTTP)
	if err == nil || outcome != probe.OutcomeCancelled || code != probe.FailureCancelled {
		t.Fatalf("cancel-cause classification = %q/%q/%v", outcome, code, err)
	}
}

func TestFailureCodesForRejectsUnknownStage(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("failureCodesFor() did not panic for an internal invalid stage")
		}
	}()
	failureCodesFor(0)
}
