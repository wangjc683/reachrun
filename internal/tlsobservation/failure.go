package tlsobservation

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/wangjc683/reachrun/internal/probe"
)

func classifyTCPFailure(
	parent context.Context,
	attempt context.Context,
	err error,
) (probe.Outcome, probe.FailureCode) {
	if errors.Is(parent.Err(), context.Canceled) {
		return probe.OutcomeCancelled, probe.FailureCancelled
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) ||
		errors.Is(attempt.Err(), context.DeadlineExceeded) || isTimeout(err) {
		return probe.OutcomeFailed, FailureTCPTimeout
	}
	if errors.Is(attempt.Err(), context.Canceled) {
		return probe.OutcomeCancelled, probe.FailureCancelled
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return probe.OutcomeFailed, FailureTCPConnectionRefused
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return probe.OutcomeFailed, FailureTCPNoRoute
	}
	if isReset(err) {
		return probe.OutcomeFailed, FailureTCPConnectionReset
	}
	return probe.OutcomeFailed, FailureTCP
}

func classifyUnconfirmedReason(err error) UnconfirmedReason {
	switch {
	case isTimeout(err):
		return UnconfirmedHandshakeTimeout
	case isReset(err):
		return UnconfirmedConnectionReset
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, net.ErrClosed):
		return UnconfirmedConnectionClosed
	default:
		return UnconfirmedHandshakeFailure
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}
