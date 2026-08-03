// Package browserplaceholder runs the bounded Phase 0 placeholder used to
// verify ReachRun's browser-opening and terminal URL fallback behavior. It is
// not the product localhost server or UI lifecycle.
package browserplaceholder

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/browseropener"
	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// SchemaVersion versions this Phase 0 capability report independently from
	// network probe envelopes.
	SchemaVersion = 1
	// Operation identifies the bounded placeholder lifecycle.
	Operation = "browser_placeholder"
)

// Status records whether the placeholder was requested, the bounded run
// stopped, or the caller cancelled it.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusStopped   Status = "stopped"
	StatusCancelled Status = "cancelled"
)

// Completion is a neutral fact. It does not claim that a successful launch
// command caused the observed HTTP request.
type Completion string

const CompletionPageRequested Completion = "page_requested"

// StopReason is a stable placeholder orchestration fact.
type StopReason string

const (
	StopListenerFailure             StopReason = "listener_failure"
	StopPlaceholderTimeout          StopReason = "placeholder_timeout"
	StopCancelled                   StopReason = "cancelled"
	StopInvalidFallbackNotifier     StopReason = "invalid_fallback_notifier"
	StopInvalidOpenerEvidence       StopReason = "invalid_opener_evidence"
	StopFallbackNotificationFailure StopReason = "fallback_notification_failure"
	StopServerFailure               StopReason = "server_failure"
)

// Config controls the bounded time in which the placeholder may be accessed.
// Listener network, address, path, HTTP policy, and opener choice are fixed.
type Config struct {
	Timeout time.Duration
}

// Input records the fixed loopback and lifecycle policy.
type Input struct {
	ListenNetwork string `json:"listen_network"`
	ListenAddress string `json:"listen_address"`
	Path          string `json:"path"`
	OpenTimeoutMS int64  `json:"open_timeout_ms"`
	TimeoutMS     int64  `json:"timeout_ms"`
}

// Fallback is delivered immediately after a valid failed browser-open attempt
// so the CLI can print a URL while the placeholder remains available.
type Fallback struct {
	URL     string                `json:"url"`
	Failure browseropener.Failure `json:"failure"`
}

// FallbackNotifier must return after displaying the fallback URL. Returning
// an error stops the spike because the user did not receive an accessible URL.
type FallbackNotifier func(Fallback) error

// PageRequest records the exact request that completed the placeholder run.
type PageRequest struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

// Result preserves the browser-open attempt and the independently observed
// placeholder request. A failed opener may still produce a completed result
// after the terminal fallback URL is requested.
type Result struct {
	SchemaVersion    int                   `json:"schema_version"`
	Operation        string                `json:"operation"`
	ObservedAt       time.Time             `json:"observed_at"`
	DurationMS       int64                 `json:"duration_ms"`
	Platform         probe.Platform        `json:"platform"`
	Input            Input                 `json:"input"`
	URL              string                `json:"url,omitempty"`
	OpenAttempt      *browseropener.Result `json:"open_attempt,omitempty"`
	FallbackNotified bool                  `json:"fallback_notified"`
	PageRequest      *PageRequest          `json:"page_request,omitempty"`
	Status           Status                `json:"status"`
	Completion       Completion            `json:"completion,omitempty"`
	StopReason       StopReason            `json:"stop_reason,omitempty"`
	Detail           string                `json:"detail,omitempty"`
}

// Runner hides the fixed listener, hardened placeholder, platform opener,
// immediate fallback notification, bounded wait, shutdown, and validation.
type Runner interface {
	Run(ctx context.Context, notifyFallback FallbackNotifier) Result
}
