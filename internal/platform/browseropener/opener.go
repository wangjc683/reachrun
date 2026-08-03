package browseropener

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var errUnsupportedPlatform = errors.New("browser opening is unsupported on this platform")

type launchFunc func(context.Context, string) error

type dependencies struct {
	backend             string
	launch              launchFunc
	beforeSuccessCommit func()
}

type opener struct {
	backend             string
	launch              launchFunc
	beforeSuccessCommit func()
}

// New returns the production platform browser opener.
func New() (Opener, error) {
	return newOpener(dependencies{backend: platformBackend, launch: launchPlatform})
}

func newOpener(deps dependencies) (*opener, error) {
	if strings.TrimSpace(deps.backend) == "" {
		return nil, errors.New("browser backend must not be empty")
	}
	if deps.launch == nil {
		return nil, errors.New("browser launch dependency must not be nil")
	}
	return &opener{
		backend:             deps.backend,
		launch:              deps.launch,
		beforeSuccessCommit: deps.beforeSuccessCommit,
	}, nil
}

func (o *opener) Open(ctx context.Context, rawURL string) Result {
	if err := validateLoopbackURL(rawURL); err != nil {
		return o.failed(rawURL, FailureInvalidURL, err)
	}
	if err := ctx.Err(); err != nil {
		return o.contextResult(rawURL, err)
	}

	err := o.launch(ctx, rawURL)
	if contextErr := ctx.Err(); contextErr != nil {
		return o.contextResult(rawURL, contextErr)
	}
	if err != nil {
		return o.failed(rawURL, classifyLaunchFailure(err), err)
	}
	if o.beforeSuccessCommit != nil {
		o.beforeSuccessCommit()
	}
	if err := ctx.Err(); err != nil {
		return o.contextResult(rawURL, err)
	}
	return Result{Backend: o.backend, URL: rawURL, Status: StatusOpened}
}

func classifyLaunchFailure(err error) FailureCode {
	switch {
	case errors.Is(err, errUnsupportedPlatform):
		return FailureUnsupportedPlatform
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist):
		return FailureCommandUnavailable
	default:
		return FailureLaunchFailed
	}
}

func (o *opener) failed(rawURL string, code FailureCode, err error) Result {
	return Result{
		Backend: o.backend,
		URL:     rawURL,
		Status:  StatusFailed,
		Failure: &Failure{Code: code, Detail: err.Error()},
	}
}

func (o *opener) cancelled(rawURL string, err error) Result {
	return Result{
		Backend: o.backend,
		URL:     rawURL,
		Status:  StatusCancelled,
		Failure: &Failure{Code: FailureCancelled, Detail: err.Error()},
	}
}

func (o *opener) contextResult(rawURL string, err error) Result {
	if errors.Is(err, context.DeadlineExceeded) {
		return o.failed(rawURL, FailureLaunchTimeout, err)
	}
	return o.cancelled(rawURL, err)
}

func validateLoopbackURL(rawURL string) error {
	if strings.ContainsAny(rawURL, "\x00\r\n") {
		return errors.New("browser URL must not contain control characters")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse browser URL: %w", err)
	}
	if parsed.Scheme != "http" || parsed.Opaque != "" || parsed.User != nil {
		return errors.New("browser URL must be an absolute HTTP URL without user information")
	}
	if parsed.Hostname() != "127.0.0.1" {
		return errors.New("browser URL must use the literal 127.0.0.1 host")
	}
	portText := parsed.Port()
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return errors.New("browser URL must include a canonical TCP port")
	}
	if parsed.Host != net.JoinHostPort("127.0.0.1", portText) {
		return errors.New("browser URL host and port must use canonical form")
	}
	if parsed.Path == "" || parsed.Path[0] != '/' {
		return errors.New("browser URL must include an absolute path")
	}
	return nil
}
