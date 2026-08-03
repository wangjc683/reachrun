package familycondition

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func classifyUnavailable(err error) (Reason, bool) {
	switch {
	case errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, windows.WSAENETUNREACH),
		errors.Is(err, windows.WSAEHOSTUNREACH):
		return ReasonNoRoute, true
	case errors.Is(err, syscall.EAFNOSUPPORT), errors.Is(err, windows.WSAEAFNOSUPPORT):
		return ReasonAddressFamilyUnsupported, true
	case errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, windows.WSAEADDRNOTAVAIL):
		return ReasonSourceAddressUnavailable, true
	case errors.Is(err, syscall.ENETDOWN), errors.Is(err, windows.WSAENETDOWN):
		return ReasonNetworkDown, true
	default:
		return "", false
	}
}
