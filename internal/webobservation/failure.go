package webobservation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/wangjc683/reachrun/internal/probe"
)

type attemptStage uint8

const (
	attemptStageTCP attemptStage = iota + 1
	attemptStageTLS
	attemptStageHTTP
)

func classifyContext(
	ctx context.Context,
	stage attemptStage,
) (probe.Outcome, probe.FailureCode, error) {
	err := ctx.Err()
	if err == nil {
		return "", "", nil
	}
	if errors.Is(err, context.Canceled) {
		return probe.OutcomeCancelled, probe.FailureCancelled, err
	}
	return probe.OutcomeFailed, timeoutCode(stage), err
}

func classifyAttemptContext(
	parent context.Context,
	attempt context.Context,
	stage attemptStage,
) (probe.Outcome, probe.FailureCode, error) {
	if outcome, code, err := classifyContext(parent, stage); err != nil {
		return outcome, code, err
	}
	return classifyContext(attempt, stage)
}

func classifyExchangeFailure(err error, stage attemptStage) probe.FailureCode {
	codes := failureCodesFor(stage)
	if isTimeout(err) {
		return codes.timeout
	}
	if isCertificateFailure(err) {
		return FailureTLSCertificate
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return FailureTCPConnectionRefused
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return FailureTCPNoRoute
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return codes.reset
	}
	return codes.fallback
}

func timeoutCode(stage attemptStage) probe.FailureCode {
	return failureCodesFor(stage).timeout
}

type stageFailureCodes struct {
	timeout  probe.FailureCode
	reset    probe.FailureCode
	fallback probe.FailureCode
}

func failureCodesFor(stage attemptStage) stageFailureCodes {
	switch stage {
	case attemptStageTCP:
		return stageFailureCodes{
			timeout:  FailureTCPTimeout,
			reset:    FailureTCPConnectionReset,
			fallback: FailureTCP,
		}
	case attemptStageTLS:
		return stageFailureCodes{
			timeout:  FailureTLSTimeout,
			reset:    FailureTLSConnectionReset,
			fallback: FailureTLSHandshake,
		}
	case attemptStageHTTP:
		return stageFailureCodes{
			timeout:  FailureHTTPTimeout,
			reset:    FailureHTTPConnectionReset,
			fallback: FailureHTTPProtocol,
		}
	default:
		panic(fmt.Sprintf("webobservation: unsupported attempt stage %d", stage))
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func isCertificateFailure(err error) bool {
	var verificationError *tls.CertificateVerificationError
	if errors.As(err, &verificationError) {
		return true
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}
	var unknownAuthorityError x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityError) {
		return true
	}
	var certificateInvalidError x509.CertificateInvalidError
	if errors.As(err, &certificateInvalidError) {
		return true
	}
	var systemRootsError x509.SystemRootsError
	return errors.As(err, &systemRootsError)
}
