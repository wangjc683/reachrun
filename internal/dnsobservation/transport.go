package dnsobservation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

type exchangeResult struct {
	message        []byte
	remoteEndpoint string
	dohStatus      int
}

type exchangeFailure struct {
	code probe.FailureCode
	err  error
}

func (f *exchangeFailure) Error() string {
	return f.err.Error()
}

func (o *observer) Observe(ctx context.Context, request Request) Result {
	startedAt := o.now()
	input, name, qtype, err := normalizeRequest(request)
	if err != nil {
		return o.failureResult(startedAt, input, probe.OutcomeFailed, probe.FailureInvalidInput, err)
	}
	if outcome, code, contextErr := classifyContextFailure(ctx, ctx); contextErr != nil {
		return o.failureResult(startedAt, input, outcome, code, contextErr)
	}

	endpoint, ok := o.endpoints[input.Resolver.ID]
	if !ok {
		return o.failureResult(
			startedAt,
			input,
			probe.OutcomeFailed,
			probe.FailureInvalidInput,
			fmt.Errorf("resolver %q is not configured", input.Resolver.ID),
		)
	}
	input.Resolver = endpoint.input(input.Transport, o.wirePort)
	if err := validateTransportEndpoint(input.Transport, endpoint); err != nil {
		return o.failureResult(startedAt, input, probe.OutcomeFailed, probe.FailureInvalidInput, err)
	}

	id := uint16(0)
	if input.Transport != TransportDoH {
		if err := binary.Read(o.random, binary.BigEndian, &id); err != nil {
			return o.failureResult(
				startedAt,
				input,
				probe.OutcomeFailed,
				FailureDNSProtocol,
				fmt.Errorf("generate DNS message id: %w", err),
			)
		}
	}
	query, err := buildQuery(id, name, qtype)
	if err != nil {
		return o.failureResult(startedAt, input, probe.OutcomeFailed, FailureDNSProtocol, err)
	}

	attemptCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	var exchange exchangeResult
	var exchangeErr *exchangeFailure
	switch input.Transport {
	case TransportUDP:
		exchange, exchangeErr = o.exchangeWire(attemptCtx, endpoint, TransportUDP, query)
	case TransportTCP:
		exchange, exchangeErr = o.exchangeWire(attemptCtx, endpoint, TransportTCP, query)
	case TransportDoH:
		exchange, exchangeErr = o.exchangeDoH(attemptCtx, endpoint, query)
	}
	if outcome, code, contextErr := classifyContextFailure(ctx, attemptCtx); contextErr != nil {
		return o.failureResult(startedAt, input, outcome, code, contextErr)
	}
	if exchangeErr != nil {
		code := exchangeErr.code
		if isTimeout(exchangeErr.err) {
			code = probe.FailureTimeout
		}
		return o.failureResult(startedAt, input, probe.OutcomeFailed, code, exchangeErr.err)
	}

	parsed, err := decodeResponse(exchange.message, expectedResponse{
		id:       id,
		name:     name,
		nameText: input.Hostname,
		qtype:    qtype,
	})
	if err != nil {
		return o.failureResult(startedAt, input, probe.OutcomeFailed, FailureDNSProtocol, err)
	}
	if outcome, code, contextErr := classifyContextFailure(ctx, attemptCtx); contextErr != nil {
		return o.failureResult(startedAt, input, outcome, code, contextErr)
	}

	evidence, err := evidenceFromResponse(
		parsed,
		input,
		len(exchange.message),
		exchange.remoteEndpoint,
		exchange.dohStatus,
	)
	if err != nil {
		return o.failureResult(startedAt, input, probe.OutcomeFailed, FailureDNSProtocol, err)
	}
	if o.beforeSuccessCommit != nil {
		o.beforeSuccessCommit()
	}
	// Evidence construction is deliberately separate from wire decoding. Check
	// cancellation once more at the final commit point so a parent cancellation
	// that races that work can never be reported as a late success.
	if outcome, code, contextErr := classifyContextFailure(ctx, attemptCtx); contextErr != nil {
		return o.failureResult(startedAt, input, outcome, code, contextErr)
	}
	result := o.baseResult(startedAt, input)
	result.Outcome = probe.OutcomeSucceeded
	result.Evidence = &evidence
	return result
}

func validateTransportEndpoint(transport Transport, endpoint configuredEndpoint) error {
	if (transport == TransportUDP || transport == TransportTCP) && endpoint.kind != endpointWire {
		return fmt.Errorf("resolver %q is not configured for %s", endpoint.id, transport)
	}
	if transport == TransportDoH && endpoint.kind != endpointDoH {
		return fmt.Errorf("resolver %q is not configured for DoH", endpoint.id)
	}
	return nil
}

func (o *observer) exchangeWire(
	ctx context.Context,
	endpoint configuredEndpoint,
	transport Transport,
	query []byte,
) (exchangeResult, *exchangeFailure) {
	address := netip.AddrPortFrom(endpoint.wireIP, o.wirePort).String()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, string(transport), address)
	if err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopClose()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
		}
	}

	if transport == TransportUDP {
		if err := writeAll(conn, query); err != nil {
			return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
		}
		buffer := make([]byte, maxDNSMessageBytes)
		n, err := conn.Read(buffer)
		if err != nil {
			return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
		}
		if err := ctx.Err(); err != nil {
			return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
		}
		return exchangeResult{
			message:        append([]byte(nil), buffer[:n]...),
			remoteEndpoint: conn.RemoteAddr().String(),
		}, nil
	}

	if len(query) > maxDNSMessageBytes {
		return exchangeResult{}, &exchangeFailure{
			code: FailureDNSProtocol,
			err:  fmt.Errorf("DNS query is too large: %d bytes", len(query)),
		}
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if err := writeAll(conn, framed); err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}

	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}
	responseLength := int(binary.BigEndian.Uint16(length[:]))
	if responseLength == 0 || responseLength > maxDNSMessageBytes {
		return exchangeResult{}, &exchangeFailure{
			code: FailureDNSProtocol,
			err:  fmt.Errorf("TCP DNS response length %d is invalid", responseLength),
		}
	}
	message := make([]byte, responseLength)
	if _, err := io.ReadFull(conn, message); err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}
	if err := ctx.Err(); err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}
	return exchangeResult{
		message:        message,
		remoteEndpoint: conn.RemoteAddr().String(),
	}, nil
}

func (o *observer) exchangeDoH(
	ctx context.Context,
	endpoint configuredEndpoint,
	query []byte,
) (exchangeResult, *exchangeFailure) {
	port, err := dohPort(endpoint.dohURL)
	if err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDoHRule, err: err}
	}
	bootstrapAddress := net.JoinHostPort(endpoint.bootstrap.String(), port)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: endpoint.dohURL.Hostname(),
		RootCAs:    o.rootCAs,
	}
	dialer := net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, requestedPort, splitErr := net.SplitHostPort(address)
			if splitErr != nil || !strings.EqualFold(host, endpoint.dohURL.Hostname()) || requestedPort != port {
				return nil, fmt.Errorf("DoH transport refused unexpected dial target %q", address)
			}
			return dialer.DialContext(dialCtx, network, bootstrapAddress)
		},
		TLSClientConfig:        tlsConfig,
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    o.timeout,
		ResponseHeaderTimeout:  o.timeout,
		MaxResponseHeaderBytes: 32 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.dohURL.String(),
		bytes.NewReader(query),
	)
	if err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDoHRule, err: err}
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")

	response, err := client.Do(request)
	if err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return exchangeResult{}, &exchangeFailure{
			code: FailureDoHRule,
			err:  fmt.Errorf("DoH server returned HTTP %d", response.StatusCode),
		}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return exchangeResult{}, &exchangeFailure{
			code: FailureDoHRule,
			err:  fmt.Errorf("DoH server returned unsupported Content-Type %q", response.Header.Get("Content-Type")),
		}
	}
	message, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessageBytes+1))
	if err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}
	if len(message) > maxDNSMessageBytes {
		return exchangeResult{}, &exchangeFailure{
			code: FailureDoHRule,
			err:  fmt.Errorf("DoH response exceeds %d bytes", maxDNSMessageBytes),
		}
	}
	if err := ctx.Err(); err != nil {
		return exchangeResult{}, &exchangeFailure{code: FailureDNSTransport, err: err}
	}
	return exchangeResult{
		message:        message,
		remoteEndpoint: bootstrapAddress,
		dohStatus:      response.StatusCode,
	}, nil
}

func (o *observer) failureResult(
	startedAt time.Time,
	input Input,
	outcome probe.Outcome,
	code probe.FailureCode,
	err error,
) Result {
	result := o.baseResult(startedAt, input)
	result.Outcome = outcome
	result.Failure = &probe.Failure{Code: code}
	if err != nil {
		result.Failure.Detail = err.Error()
	}
	return result
}

func classifyContextFailure(
	parent context.Context,
	attempt context.Context,
) (probe.Outcome, probe.FailureCode, error) {
	if errors.Is(parent.Err(), context.Canceled) || errors.Is(attempt.Err(), context.Canceled) {
		return probe.OutcomeCancelled, probe.FailureCancelled, context.Canceled
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) ||
		errors.Is(attempt.Err(), context.DeadlineExceeded) {
		return probe.OutcomeFailed, probe.FailureTimeout, context.DeadlineExceeded
	}
	return "", "", nil
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}

func dohPort(u *url.URL) (string, error) {
	port := u.Port()
	if port == "" {
		return "443", nil
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return "", fmt.Errorf("DoH URL has invalid port %q", port)
	}
	if strconv.FormatUint(parsed, 10) != port {
		return "", fmt.Errorf("DoH URL has non-canonical port %q", port)
	}
	return port, nil
}
