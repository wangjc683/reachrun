package browserplaceholder

import (
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/browseropener"
)

// Validate checks the placeholder lifecycle, opener evidence, terminal shape,
// and exact loopback request contract.
func Validate(result Result) error {
	if result.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if result.Operation != Operation {
		return fmt.Errorf("operation must be %q", Operation)
	}
	if result.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at must not be zero")
	}
	if _, offset := result.ObservedAt.Zone(); offset != 0 {
		return fmt.Errorf("observed_at must use UTC")
	}
	if result.DurationMS < 0 {
		return fmt.Errorf("duration_ms must not be negative")
	}
	if result.Platform.OS == "" || result.Platform.Arch == "" {
		return fmt.Errorf("platform must include OS and architecture")
	}
	if result.Input.TimeoutMS < 1 || result.Input.TimeoutMS > maximumTimeout.Milliseconds() {
		return fmt.Errorf("input does not match the fixed placeholder policy")
	}
	timeout := time.Duration(result.Input.TimeoutMS) * time.Millisecond
	if timeout < time.Millisecond || timeout > maximumTimeout ||
		!reflect.DeepEqual(result.Input, fixedInput(timeout)) {
		return fmt.Errorf("input does not match the fixed placeholder policy")
	}
	if err := validateTerminalShape(result); err != nil {
		return err
	}
	if result.URL != "" {
		if err := validateResultURL(result.URL); err != nil {
			return err
		}
	}

	if result.OpenAttempt != nil {
		if result.URL == "" {
			return fmt.Errorf("open attempt requires URL")
		}
		if err := browseropener.Validate(*result.OpenAttempt, result.URL); err != nil {
			return fmt.Errorf("invalid browser opener evidence: %w", err)
		}
		if result.OpenAttempt.Status == browseropener.StatusCancelled && result.Status != StatusCancelled {
			return fmt.Errorf("cancelled opener requires cancelled placeholder")
		}
	}
	if result.FallbackNotified {
		if result.OpenAttempt == nil || result.OpenAttempt.Status != browseropener.StatusFailed {
			return fmt.Errorf("fallback notification requires a failed open attempt")
		}
	}

	if result.PageRequest != nil {
		parsed, err := url.Parse(result.URL)
		if err != nil {
			return fmt.Errorf("parse result URL: %w", err)
		}
		expected := PageRequest{Method: "GET", Host: parsed.Host, Path: pagePath}
		if *result.PageRequest != expected {
			return fmt.Errorf("page request does not match the exact placeholder URL")
		}
	}
	return nil
}

func validateTerminalShape(result Result) error {
	switch result.Status {
	case StatusCompleted:
		if result.Completion != CompletionPageRequested || result.StopReason != "" || result.Detail != "" ||
			result.URL == "" || result.OpenAttempt == nil || result.PageRequest == nil {
			return fmt.Errorf("completed placeholder requires URL, opener, page request, and page_requested completion")
		}
		if result.OpenAttempt.Status == browseropener.StatusFailed && !result.FallbackNotified {
			return fmt.Errorf("completed failed opener requires terminal fallback notification")
		}
		if result.OpenAttempt.Status == browseropener.StatusOpened && result.FallbackNotified {
			return fmt.Errorf("opened browser attempt must not notify fallback")
		}
	case StatusStopped:
		if result.Completion != "" || result.PageRequest != nil || strings.TrimSpace(result.Detail) == "" {
			return fmt.Errorf("stopped placeholder requires detail without completion or page request")
		}
		switch result.StopReason {
		case StopListenerFailure, StopInvalidFallbackNotifier:
			if result.URL != "" || result.OpenAttempt != nil || result.FallbackNotified {
				return fmt.Errorf("%s must not include URL or opener evidence", result.StopReason)
			}
		case StopPlaceholderTimeout:
			if result.URL == "" || result.OpenAttempt == nil {
				return fmt.Errorf("%s requires URL and opener evidence", result.StopReason)
			}
		case StopFallbackNotificationFailure:
			if result.URL == "" || result.OpenAttempt == nil {
				return fmt.Errorf("%s requires URL and opener evidence", result.StopReason)
			}
			if result.OpenAttempt.Status != browseropener.StatusFailed || result.FallbackNotified {
				return fmt.Errorf("fallback notification failure requires an unnotified failed opener")
			}
		case StopServerFailure:
			if result.URL == "" {
				return fmt.Errorf("server failure requires URL")
			}
		case StopInvalidOpenerEvidence:
			if result.URL == "" || result.OpenAttempt != nil || result.FallbackNotified {
				return fmt.Errorf("invalid opener evidence keeps URL but discards the invalid attempt")
			}
		default:
			return fmt.Errorf("stopped placeholder has unsupported reason %q", result.StopReason)
		}
	case StatusCancelled:
		if result.Completion != "" || result.StopReason != StopCancelled ||
			strings.TrimSpace(result.Detail) == "" || result.PageRequest != nil {
			return fmt.Errorf("cancelled placeholder requires cancelled reason without completion")
		}
	default:
		return fmt.Errorf("unsupported status %q", result.Status)
	}
	return nil
}

func validateResultURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse result URL: %w", err)
	}
	portText := parsed.Port()
	port, portErr := strconv.Atoi(portText)
	if parsed.Scheme != "http" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Hostname() != "127.0.0.1" ||
		portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText ||
		parsed.Host != net.JoinHostPort("127.0.0.1", portText) ||
		parsed.Path != pagePath || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("URL must be the canonical placeholder loopback URL")
	}
	return nil
}
