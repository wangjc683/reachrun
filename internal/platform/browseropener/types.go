// Package browseropener opens one validated ReachRun loopback URL in the
// platform's default browser. It owns platform launch selection and stable
// failure classification; callers never construct shell commands.
package browseropener

import "context"

// Status records whether the platform accepted the launch command, the
// attempt failed and needs terminal fallback, or the caller cancelled it.
type Status string

const (
	StatusOpened    Status = "opened"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// FailureCode is a stable platform-launch category. Detail may retain the raw
// platform error for Phase 0 diagnostics but must not drive product behavior.
type FailureCode string

const (
	FailureInvalidURL          FailureCode = "invalid_url"
	FailureCommandUnavailable  FailureCode = "command_unavailable"
	FailureLaunchTimeout       FailureCode = "launch_timeout"
	FailureLaunchFailed        FailureCode = "launch_failed"
	FailureUnsupportedPlatform FailureCode = "unsupported_platform"
	FailureCancelled           FailureCode = "cancelled"
)

// Failure describes why the browser launch was not accepted.
type Failure struct {
	Code   FailureCode `json:"code"`
	Detail string      `json:"detail"`
}

// Result is one platform launch attempt. Opened only means the platform
// command was accepted; a caller must separately observe the page request.
type Result struct {
	Backend string   `json:"backend"`
	URL     string   `json:"url"`
	Status  Status   `json:"status"`
	Failure *Failure `json:"failure,omitempty"`
}

// Opener hides loopback URL validation and the platform launch mechanism.
type Opener interface {
	Open(ctx context.Context, rawURL string) Result
}
