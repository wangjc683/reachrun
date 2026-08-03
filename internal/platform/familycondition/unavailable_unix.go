//go:build !windows

package familycondition

import (
	"errors"
	"syscall"
)

func classifyUnavailable(err error) (Reason, bool) {
	switch {
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return ReasonNoRoute, true
	case errors.Is(err, syscall.EAFNOSUPPORT):
		return ReasonAddressFamilyUnsupported, true
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return ReasonSourceAddressUnavailable, true
	case errors.Is(err, syscall.ENETDOWN):
		return ReasonNetworkDown, true
	default:
		return "", false
	}
}
