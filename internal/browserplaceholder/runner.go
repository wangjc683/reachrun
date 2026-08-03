package browserplaceholder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/browseropener"
	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	defaultTimeout     = 60 * time.Second
	maximumTimeout     = 2 * time.Minute
	listenNetwork      = "tcp4"
	listenAddress      = "127.0.0.1:0"
	pagePath           = "/"
	browserOpenTimeout = 5 * time.Second
	maxHeaderBytes     = 16 * 1024
)

const placeholderHTML = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ReachRun Browser Check</title><main><h1>ReachRun browser check</h1><p>The local placeholder page is reachable. You may close this tab.</p></main></html>"

type listenFunc func(string, string) (net.Listener, error)

type dependencies struct {
	now                 func() time.Time
	platform            probe.Platform
	opener              browseropener.Opener
	listen              listenFunc
	beforeSuccessCommit func()
}

type runner struct {
	timeout             time.Duration
	now                 func() time.Time
	platform            probe.Platform
	opener              browseropener.Opener
	listen              listenFunc
	beforeSuccessCommit func()
}

type terminal struct {
	status Status
	reason StopReason
	detail string
}

// New creates the production Phase 0 browser placeholder runner.
func New(config Config) (Runner, error) {
	opener, err := browseropener.New()
	if err != nil {
		return nil, fmt.Errorf("create platform browser opener: %w", err)
	}
	return newRunner(config, dependencies{opener: opener})
}

func newRunner(config Config, deps dependencies) (*runner, error) {
	timeout, err := normalizeTimeout(config.Timeout)
	if err != nil {
		return nil, err
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.platform.OS == "" && deps.platform.Arch == "" {
		deps.platform = probe.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}
	}
	if deps.platform.OS == "" || deps.platform.Arch == "" {
		return nil, errors.New("platform dependency must include OS and architecture")
	}
	if deps.opener == nil {
		return nil, errors.New("browser opener dependency must not be nil")
	}
	if deps.listen == nil {
		deps.listen = net.Listen
	}
	return &runner{
		timeout:             timeout,
		now:                 deps.now,
		platform:            deps.platform,
		opener:              deps.opener,
		listen:              deps.listen,
		beforeSuccessCommit: deps.beforeSuccessCommit,
	}, nil
}

func normalizeTimeout(timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		return defaultTimeout, nil
	}
	if timeout < time.Millisecond || timeout > maximumTimeout {
		return 0, fmt.Errorf("timeout must be between %s and %s", time.Millisecond, maximumTimeout)
	}
	return timeout, nil
}

func (r *runner) Run(ctx context.Context, notifyFallback FallbackNotifier) Result {
	startedAt := r.now()
	input := fixedInput(r.timeout)
	if notifyFallback == nil {
		return r.finish(startedAt, input, "", nil, false, nil, terminal{
			status: StatusStopped,
			reason: StopInvalidFallbackNotifier,
			detail: "fallback notifier must not be nil",
		})
	}
	if state, ok := contextTerminal(ctx); ok {
		return r.finish(startedAt, input, "", nil, false, nil, state)
	}

	runContext, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	listener, err := r.listen(listenNetwork, listenAddress)
	if err != nil {
		return r.finish(startedAt, input, "", nil, false, nil, terminal{
			status: StatusStopped,
			reason: StopListenerFailure,
			detail: fmt.Sprintf("listen on %s/%s: %v", listenNetwork, listenAddress, err),
		})
	}

	rawURL, expectedHost, err := listenerURL(listener)
	if err != nil {
		_ = listener.Close()
		return r.finish(startedAt, input, "", nil, false, nil, terminal{
			status: StatusStopped,
			reason: StopListenerFailure,
			detail: err.Error(),
		})
	}
	pageRequests := make(chan PageRequest, 1)
	handler := placeholderHandler(expectedHost, pageRequests)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: min(r.timeout, 5*time.Second),
		IdleTimeout:       min(r.timeout, 5*time.Second),
		MaxHeaderBytes:    maxHeaderBytes,
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()

	if serveErr, stopped := immediateServeFailure(serveErrors); stopped {
		return r.finish(startedAt, input, rawURL, nil, false, nil, terminal{
			status: StatusStopped,
			reason: StopServerFailure,
			detail: serveErr.Error(),
		})
	}

	openContext, cancelOpen := context.WithTimeout(runContext, min(r.timeout, browserOpenTimeout))
	openAttempt := r.opener.Open(openContext, rawURL)
	cancelOpen()
	if err := browseropener.Validate(openAttempt, rawURL); err != nil {
		closeServer(server, serveErrors)
		return r.finish(startedAt, input, rawURL, nil, false, nil, terminal{
			status: StatusStopped,
			reason: StopInvalidOpenerEvidence,
			detail: err.Error(),
		})
	}
	if state, ok := contextTerminal(runContext); ok {
		closeServer(server, serveErrors)
		return r.finish(startedAt, input, rawURL, &openAttempt, false, nil, state)
	}
	if openAttempt.Status == browseropener.StatusCancelled {
		closeServer(server, serveErrors)
		return r.finish(startedAt, input, rawURL, nil, false, nil, terminal{
			status: StatusStopped,
			reason: StopInvalidOpenerEvidence,
			detail: "browser opener returned cancellation while the placeholder was active",
		})
	}
	if serveErr, stopped := immediateServeFailure(serveErrors); stopped {
		return r.finish(startedAt, input, rawURL, &openAttempt, false, nil, terminal{
			status: StatusStopped,
			reason: StopServerFailure,
			detail: serveErr.Error(),
		})
	}

	fallbackNotified := false
	if openAttempt.Status == browseropener.StatusFailed {
		fallback := Fallback{URL: rawURL, Failure: *openAttempt.Failure}
		if err := notifyFallback(fallback); err != nil {
			closeServer(server, serveErrors)
			return r.finish(startedAt, input, rawURL, &openAttempt, false, nil, terminal{
				status: StatusStopped,
				reason: StopFallbackNotificationFailure,
				detail: fmt.Sprintf("display browser fallback: %v", err),
			})
		}
		fallbackNotified = true
	}

	for {
		select {
		case request := <-pageRequests:
			closeServer(server, serveErrors)
			if state, ok := contextTerminal(runContext); ok {
				return r.finish(startedAt, input, rawURL, &openAttempt, fallbackNotified, nil, state)
			}
			if r.beforeSuccessCommit != nil {
				r.beforeSuccessCommit()
			}
			if state, ok := contextTerminal(runContext); ok {
				return r.finish(startedAt, input, rawURL, &openAttempt, fallbackNotified, nil, state)
			}
			return r.finish(startedAt, input, rawURL, &openAttempt, fallbackNotified, &request, terminal{
				status: StatusCompleted,
			})
		case serveErr := <-serveErrors:
			if errors.Is(serveErr, http.ErrServerClosed) {
				serveErr = errors.New("placeholder server closed before a valid page request")
			}
			return r.finish(startedAt, input, rawURL, &openAttempt, fallbackNotified, nil, terminal{
				status: StatusStopped,
				reason: StopServerFailure,
				detail: serveErr.Error(),
			})
		case <-runContext.Done():
			closeServer(server, serveErrors)
			state, _ := contextTerminal(runContext)
			return r.finish(startedAt, input, rawURL, &openAttempt, fallbackNotified, nil, state)
		}
	}
}

func fixedInput(timeout time.Duration) Input {
	return Input{
		ListenNetwork: listenNetwork,
		ListenAddress: listenAddress,
		Path:          pagePath,
		OpenTimeoutMS: min(timeout, browserOpenTimeout).Milliseconds(),
		TimeoutMS:     timeout.Milliseconds(),
	}
}

func listenerURL(listener net.Listener) (string, string, error) {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) ||
		address.Port < 1 || address.Port > 65535 {
		return "", "", fmt.Errorf("listener returned an invalid TCP address %q", listener.Addr())
	}
	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(address.Port))
	return "http://" + host + pagePath, host, nil
}

func placeholderHandler(expectedHost string, requested chan<- PageRequest) http.Handler {
	var complete sync.Once
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		setPlaceholderHeaders(response.Header())
		if request.Host != expectedHost {
			http.Error(response, "invalid Host", http.StatusMisdirectedRequest)
			return
		}
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if request.URL.Path != pagePath || request.URL.RawQuery != "" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Header().Set("Content-Length", strconv.Itoa(len(placeholderHTML)))
		response.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(response, placeholderHTML); err != nil {
			return
		}
		complete.Do(func() {
			requested <- PageRequest{Method: request.Method, Host: request.Host, Path: request.URL.Path}
		})
	})
}

func setPlaceholderHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
}

func immediateServeFailure(serveErrors <-chan error) (error, bool) {
	select {
	case err := <-serveErrors:
		if err == nil {
			err = errors.New("placeholder server stopped without an error")
		}
		return err, true
	default:
		return nil, false
	}
}

func closeServer(server *http.Server, serveErrors <-chan error) {
	_ = server.Close()
	<-serveErrors
}

func contextTerminal(ctx context.Context) (terminal, bool) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return terminal{status: StatusCancelled, reason: StopCancelled, detail: ctx.Err().Error()}, true
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return terminal{status: StatusStopped, reason: StopPlaceholderTimeout, detail: ctx.Err().Error()}, true
	}
	return terminal{}, false
}

func (r *runner) finish(
	startedAt time.Time,
	input Input,
	rawURL string,
	openAttempt *browseropener.Result,
	fallbackNotified bool,
	pageRequest *PageRequest,
	state terminal,
) Result {
	finishedAt := r.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	var attemptCopy *browseropener.Result
	if openAttempt != nil {
		copy := *openAttempt
		if copy.Failure != nil {
			failure := *copy.Failure
			copy.Failure = &failure
		}
		attemptCopy = &copy
	}
	var requestCopy *PageRequest
	if pageRequest != nil {
		copy := *pageRequest
		requestCopy = &copy
	}
	completion := Completion("")
	if state.status == StatusCompleted {
		completion = CompletionPageRequested
	}
	return Result{
		SchemaVersion:    SchemaVersion,
		Operation:        Operation,
		ObservedAt:       finishedAt.UTC(),
		DurationMS:       duration,
		Platform:         r.platform,
		Input:            input,
		URL:              rawURL,
		OpenAttempt:      attemptCopy,
		FallbackNotified: fallbackNotified,
		PageRequest:      requestCopy,
		Status:           state.status,
		Completion:       completion,
		StopReason:       state.reason,
		Detail:           state.detail,
	}
}
