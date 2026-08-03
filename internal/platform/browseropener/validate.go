package browseropener

import (
	"fmt"
	"strings"
)

// Validate checks one browser-launch result against the exact requested URL.
func Validate(result Result, expectedURL string) error {
	if strings.TrimSpace(result.Backend) == "" {
		return fmt.Errorf("backend must not be empty")
	}
	if result.URL != expectedURL {
		return fmt.Errorf("URL must match the requested URL")
	}
	urlErr := validateLoopbackURL(expectedURL)

	switch result.Status {
	case StatusOpened:
		if urlErr != nil {
			return fmt.Errorf("opened result has invalid URL: %w", urlErr)
		}
		if result.Failure != nil {
			return fmt.Errorf("opened result must not include failure")
		}
	case StatusFailed:
		if result.Failure == nil || strings.TrimSpace(result.Failure.Detail) == "" {
			return fmt.Errorf("failed result requires failure detail")
		}
		if urlErr != nil {
			if result.Failure.Code != FailureInvalidURL {
				return fmt.Errorf("invalid URL requires invalid_url failure")
			}
			return nil
		}
		switch result.Failure.Code {
		case FailureCommandUnavailable, FailureLaunchTimeout, FailureLaunchFailed, FailureUnsupportedPlatform:
		default:
			return fmt.Errorf("failed result has unsupported failure code %q", result.Failure.Code)
		}
	case StatusCancelled:
		if urlErr != nil {
			return fmt.Errorf("cancelled result has invalid URL: %w", urlErr)
		}
		if result.Failure == nil || result.Failure.Code != FailureCancelled ||
			strings.TrimSpace(result.Failure.Detail) == "" {
			return fmt.Errorf("cancelled result requires cancelled failure")
		}
	default:
		return fmt.Errorf("unsupported status %q", result.Status)
	}
	return nil
}
