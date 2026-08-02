package webpath

import (
	"context"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver/systemresolvertest"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
	"github.com/wangjc683/reachrun/internal/webobservation/webobservationtest"
)

const (
	testHostname = "example.com"
	testIPv4One  = "8.8.8.8"
	testIPv4Two  = "1.1.1.1"
	testIPv6One  = "2606:4700:4700::1111"
	testIPv6Two  = "2001:4860:4860::8888"
)

func TestObserveCompletesSafeCrossHostRedirect(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(
		resolutionSuccess(testHostname, testIPv4One),
		resolutionSuccess("www.example.com", testIPv4Two),
	)
	web := webobservationtest.New(
		webSuccess(
			webobservation.SchemeHTTPS,
			testHostname,
			testIPv4One,
			"/",
			"",
			302,
			"https://WWW.Example.COM.:443/final/%2Fpath?source=reachrun#ignored",
		),
		webSuccess(
			webobservation.SchemeHTTPS,
			"www.example.com",
			testIPv4Two,
			"/final/%2Fpath",
			"source=reachrun",
			204,
			"",
		),
	)
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(context.Background(), Request{Hostname: " EXAMPLE.COM. "})
	assertValidResult(t, result)
	if result.Status != StatusCompleted || result.StopReason != StopFinalResponse ||
		result.RedirectsFollowed != 1 || result.HTTPFallbackUsed || len(result.Hops) != 2 {
		t.Fatalf("result = %#v, want completed one-redirect HTTPS path", result)
	}
	if result.Hops[1].URL != "https://www.example.com/final/%2Fpath?source=reachrun" {
		t.Fatalf("second hop URL = %q", result.Hops[1].URL)
	}

	wantResolverCalls := []systemresolvertest.Call{
		{Hostname: testHostname},
		{Hostname: "www.example.com"},
	}
	if calls := resolver.Calls(); !reflect.DeepEqual(calls, wantResolverCalls) {
		t.Fatalf("resolver calls = %#v, want %#v", calls, wantResolverCalls)
	}
	wantWebCalls := []webobservationtest.Call{
		{Request: webobservation.Request{
			Scheme: webobservation.SchemeHTTPS, Hostname: testHostname,
			DialIP: testIPv4One, Path: "/",
		}},
		{Request: webobservation.Request{
			Scheme: webobservation.SchemeHTTPS, Hostname: "www.example.com",
			DialIP: testIPv4Two, Path: "/final/%2Fpath", RawQuery: "source=reachrun",
		}},
	}
	if calls := web.Calls(); !reflect.DeepEqual(calls, wantWebCalls) {
		t.Fatalf("Web calls = %#v, want %#v", calls, wantWebCalls)
	}
}

func TestObserveFallsBackToHTTPOnlyAfterAllHTTPSCandidatesFail(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(
		resolutionSuccess(testHostname, testIPv4One, testIPv4Two),
		resolutionSuccess(testHostname, testIPv4One, testIPv4Two),
	)
	web := webobservationtest.New(
		webFailure(webobservation.SchemeHTTPS, testHostname, testIPv4One, "/", webobservation.FailureTLSCertificate),
		webFailure(webobservation.SchemeHTTPS, testHostname, testIPv4Two, "/", webobservation.FailureTCPTimeout),
		webSuccess(webobservation.SchemeHTTP, testHostname, testIPv4One, "/", "", 200, ""),
	)
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(context.Background(), Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusCompleted || !result.HTTPFallbackUsed ||
		len(result.Hops) != 2 || len(result.Hops[0].Attempts) != 2 ||
		result.Hops[1].URL != "http://example.com/" {
		t.Fatalf("result = %#v, want successful bounded HTTP fallback", result)
	}
	if calls := resolver.Calls(); len(calls) != 2 {
		t.Fatalf("resolver calls = %d, want fresh resolution for HTTPS and HTTP", len(calls))
	}
}

func TestObserveTreatsAnyNonRedirectHTTPStatusAsCompleted(t *testing.T) {
	t.Parallel()

	for _, status := range []int{404, 500} {
		status := status
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			resolver := systemresolvertest.New(resolutionSuccess(testHostname, testIPv4One))
			web := webobservationtest.New(
				webSuccess(webobservation.SchemeHTTPS, testHostname, testIPv4One, "/", "", status, ""),
			)
			observer := mustObserver(t, resolver, web)

			result := observer.Observe(context.Background(), Request{Hostname: testHostname})
			assertValidResult(t, result)
			if result.Status != StatusCompleted || result.StopReason != StopFinalResponse ||
				result.HTTPFallbackUsed || len(result.Hops) != 1 {
				t.Fatalf("status %d result = %#v, want completed HTTPS path", status, result)
			}
		})
	}
}

func TestObservePreservesRespondingOriginWhenRedirectResolutionFails(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(
		resolutionSuccess(testHostname, testIPv4One),
		resolutionFailure("next.example", probe.FailureNameUnresolved),
	)
	web := webobservationtest.New(
		webSuccess(
			webobservation.SchemeHTTPS,
			testHostname,
			testIPv4One,
			"/",
			"",
			301,
			"https://next.example/landing",
		),
	)
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(context.Background(), Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusStopped || result.StopReason != StopResolutionFailed ||
		result.RedirectsFollowed != 1 || result.HTTPFallbackUsed || len(result.Hops) != 2 ||
		result.Hops[0].Attempts[0].Outcome != probe.OutcomeSucceeded {
		t.Fatalf("result = %#v, want responding origin and failed redirect target", result)
	}
	if len(web.Calls()) != 1 {
		t.Fatalf("Web calls = %#v, want no attempt without redirect resolution", web.Calls())
	}
}

func TestObserveNeverConnectsToPrivateRedirectResolution(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(
		resolutionSuccess(testHostname, testIPv4One),
		resolutionSuccess("private.example", "127.0.0.1", "10.0.0.1"),
	)
	web := webobservationtest.New(
		webSuccess(
			webobservation.SchemeHTTPS,
			testHostname,
			testIPv4One,
			"/",
			"",
			302,
			"https://private.example/admin",
		),
	)
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(context.Background(), Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusStopped || result.StopReason != StopNoPublicCandidates ||
		len(result.Hops) != 2 || len(result.Hops[1].Attempts) != 0 {
		t.Fatalf("result = %#v, want blocked private redirect target", result)
	}
	if len(web.Calls()) != 1 {
		t.Fatalf("Web calls = %#v, want no private connection", web.Calls())
	}
}

func TestObserveRejectsUnsafeRedirectBeforeResolution(t *testing.T) {
	t.Parallel()

	for name, location := range map[string]string{
		"credentials":     "https://user:secret@next.example/",
		"non-HTTP scheme": "ftp://next.example/file",
		"custom port":     "https://next.example:8443/",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolver := systemresolvertest.New(resolutionSuccess(testHostname, testIPv4One))
			web := webobservationtest.New(
				webSuccess(webobservation.SchemeHTTPS, testHostname, testIPv4One, "/", "", 302, location),
			)
			observer := mustObserver(t, resolver, web)

			result := observer.Observe(context.Background(), Request{Hostname: testHostname})
			assertValidResult(t, result)
			if result.Status != StatusStopped || result.StopReason != StopRedirectTargetUnsafe {
				t.Fatalf("result = %#v, want unsafe redirect stop", result)
			}
			if len(resolver.Calls()) != 1 || len(web.Calls()) != 1 {
				t.Fatalf("calls after unsafe redirect = resolver %#v, Web %#v", resolver.Calls(), web.Calls())
			}
		})
	}
}

func TestObserveDetectsRedirectLoop(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(
		resolutionSuccess(testHostname, testIPv4One),
		resolutionSuccess(testHostname, testIPv4One),
	)
	web := webobservationtest.New(
		webSuccess(webobservation.SchemeHTTPS, testHostname, testIPv4One, "/", "", 302, "/again"),
		webSuccess(webobservation.SchemeHTTPS, testHostname, testIPv4One, "/again", "", 302, "/"),
	)
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(context.Background(), Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusStopped || result.StopReason != StopRedirectLoop ||
		result.RedirectsFollowed != 1 || len(result.Hops) != 2 {
		t.Fatalf("result = %#v, want one followed redirect then loop", result)
	}
}

func TestObserveStopsAfterThreeRedirects(t *testing.T) {
	t.Parallel()

	resolverResults := make([]systemresolver.Result, 4)
	webResults := make([]webobservation.Result, 4)
	for index := range 4 {
		path := "/"
		if index > 0 {
			path = "/" + string(rune('0'+index))
		}
		next := "/" + string(rune('0'+index+1))
		resolverResults[index] = resolutionSuccess(testHostname, testIPv4One)
		webResults[index] = webSuccess(
			webobservation.SchemeHTTPS,
			testHostname,
			testIPv4One,
			path,
			"",
			302,
			next,
		)
	}
	resolver := systemresolvertest.New(resolverResults...)
	web := webobservationtest.New(webResults...)
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(context.Background(), Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusStopped || result.StopReason != StopRedirectLimit ||
		result.RedirectsFollowed != redirectLimit || len(result.Hops) != redirectLimit+1 {
		t.Fatalf("result = %#v, want redirect limit", result)
	}
}

func TestObserveCapsCandidatesPerAddressFamilyInResolverOrder(t *testing.T) {
	t.Parallel()

	addresses := []string{
		testIPv4One,
		"9.9.9.9",
		"208.67.222.222",
		testIPv6One,
		testIPv6Two,
		"2620:119:35::35",
	}
	resolver := systemresolvertest.New(resolutionSuccess(testHostname, addresses...))
	web := webobservationtest.New(
		webFailure(webobservation.SchemeHTTPS, testHostname, testIPv4One, "/", webobservation.FailureTCPTimeout),
		webFailure(webobservation.SchemeHTTPS, testHostname, "9.9.9.9", "/", webobservation.FailureTCPTimeout),
		webFailure(webobservation.SchemeHTTPS, testHostname, testIPv6One, "/", webobservation.FailureTCPTimeout),
		webSuccess(webobservation.SchemeHTTPS, testHostname, testIPv6Two, "/", "", 200, ""),
	)
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(context.Background(), Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusCompleted || len(result.Hops) != 1 || len(result.Hops[0].Attempts) != 4 {
		t.Fatalf("result = %#v, want four bounded attempts", result)
	}
	wantIPs := []string{testIPv4One, "9.9.9.9", testIPv6One, testIPv6Two}
	for index, call := range web.Calls() {
		if call.Request.DialIP != wantIPs[index] {
			t.Fatalf("call %d IP = %q, want %q", index, call.Request.DialIP, wantIPs[index])
		}
	}
}

func TestObserveBoundsEachWebAttemptContext(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(resolutionSuccess(testHostname, testIPv4One))
	web := webObserverAdapter(func(
		ctx context.Context,
		request webobservation.Request,
	) webobservation.Result {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("Web attempt context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > perProbeTimeout {
			t.Fatalf("Web attempt deadline remaining = %s, want (0, %s]", remaining, perProbeTimeout)
		}
		return webSuccess(
			request.Scheme,
			request.Hostname,
			request.DialIP,
			request.Path,
			request.RawQuery,
			204,
			"",
		)
	})
	result := mustObserver(t, resolver, web).Observe(
		context.Background(),
		Request{Hostname: testHostname},
	)
	assertValidResult(t, result)
	if result.Status != StatusCompleted {
		t.Fatalf("result = %#v, want completed", result)
	}
}

func TestObserveCancellationBeforeResolutionIsTerminal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := systemresolvertest.New()
	web := webobservationtest.New()
	observer := mustObserver(t, resolver, web)

	result := observer.Observe(ctx, Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusCancelled || result.StopReason != StopCancelled || len(result.Hops) != 0 {
		t.Fatalf("result = %#v, want cancelled with no work", result)
	}
	if len(resolver.Calls()) != 0 || len(web.Calls()) != 0 {
		t.Fatalf("cancelled observation called dependencies")
	}
}

func TestObserveTotalDeadlineStopsBeforeHTTPFallback(t *testing.T) {
	t.Parallel()

	resolver := resolverAdapter(func(ctx context.Context, hostname string) systemresolver.Result {
		<-ctx.Done()
		return systemResult(
			hostname,
			probe.OutcomeFailed,
			nil,
			&probe.Failure{Code: probe.FailureTimeout, Detail: ctx.Err().Error()},
		)
	})
	web := webobservationtest.New()
	observer, err := newObserver(Config{Timeout: 10 * time.Millisecond}, dependencies{
		now: time.Now, platform: testPlatform(), resolver: resolver, web: web,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}

	result := observer.Observe(context.Background(), Request{Hostname: testHostname})
	assertValidResult(t, result)
	if result.Status != StatusStopped || result.StopReason != StopPathTimeout ||
		result.HTTPFallbackUsed || len(result.Hops) != 1 {
		t.Fatalf("result = %#v, want bounded path timeout without fallback", result)
	}
	if len(web.Calls()) != 0 {
		t.Fatalf("Web calls = %#v, want none after resolution timeout", web.Calls())
	}
}

func TestObserveStopsOnMismatchedDependencyEvidence(t *testing.T) {
	t.Parallel()

	t.Run("resolution hostname", func(t *testing.T) {
		t.Parallel()
		resolver := systemresolvertest.New(resolutionSuccess("other.example", testIPv4One))
		web := webobservationtest.New()
		result := mustObserver(t, resolver, web).Observe(
			context.Background(),
			Request{Hostname: testHostname},
		)
		assertValidResult(t, result)
		if result.Status != StatusStopped || result.StopReason != StopInvalidProbeEvidence ||
			len(result.Hops) != 0 || len(web.Calls()) != 0 {
			t.Fatalf("result = %#v, want invalid mismatched resolution evidence", result)
		}
	})

	t.Run("Web target", func(t *testing.T) {
		t.Parallel()
		resolver := systemresolvertest.New(resolutionSuccess(testHostname, testIPv4One))
		web := webobservationtest.New(
			webSuccess(webobservation.SchemeHTTPS, testHostname, testIPv4Two, "/", "", 204, ""),
		)
		result := mustObserver(t, resolver, web).Observe(
			context.Background(),
			Request{Hostname: testHostname},
		)
		assertValidResult(t, result)
		if result.Status != StatusStopped || result.StopReason != StopInvalidProbeEvidence ||
			len(result.Hops) != 1 || len(result.Hops[0].Attempts) != 0 {
			t.Fatalf("result = %#v, want invalid mismatched Web evidence", result)
		}
	})
}

func TestNewValidatesConfigAndDependencies(t *testing.T) {
	t.Parallel()

	if _, err := New(Config{Timeout: -1}); err == nil {
		t.Fatal("New(negative timeout) error = nil")
	}
	if _, err := New(Config{Timeout: maximumTimeout + 1}); err == nil {
		t.Fatal("New(too-large timeout) error = nil")
	}
	if _, err := newObserver(Config{}, dependencies{}); err == nil {
		t.Fatal("newObserver(nil dependencies) error = nil")
	}
}

func mustObserver(
	t *testing.T,
	resolver systemresolver.Resolver,
	web webobservation.Observer,
) *observer {
	t.Helper()
	observer, err := newObserver(Config{}, dependencies{
		now:      time.Now,
		platform: testPlatform(),
		resolver: resolver,
		web:      web,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	return observer
}

func assertValidResult(t *testing.T, result Result) {
	t.Helper()
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
}

func resolutionSuccess(hostname string, addresses ...string) systemresolver.Result {
	evidence := systemresolver.Evidence{Addresses: make([]systemresolver.Address, 0, len(addresses))}
	for _, address := range addresses {
		parsed := netip.MustParseAddr(address).Unmap()
		family := systemresolver.FamilyIPv6
		if parsed.Is4() {
			family = systemresolver.FamilyIPv4
		}
		evidence.Addresses = append(evidence.Addresses, systemresolver.Address{
			IP: parsed.String(), Family: family,
		})
	}
	return systemResult(hostname, probe.OutcomeSucceeded, &evidence, nil)
}

func resolutionFailure(hostname string, code probe.FailureCode) systemresolver.Result {
	return systemResult(
		hostname,
		probe.OutcomeFailed,
		nil,
		&probe.Failure{Code: code, Detail: "scripted resolution failure"},
	)
}

func systemResult(
	hostname string,
	outcome probe.Outcome,
	evidence *systemresolver.Evidence,
	failure *probe.Failure,
) systemresolver.Result {
	return systemresolver.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindSystemResolution,
		ObservedAt:    testObservedAt(),
		DurationMS:    1,
		Platform:      testPlatform(),
		Source:        testSource(),
		Input:         systemresolver.Input{Hostname: hostname},
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func webSuccess(
	scheme webobservation.Scheme,
	hostname string,
	dialIP string,
	path string,
	rawQuery string,
	status int,
	location string,
) webobservation.Result {
	input := webInput(scheme, hostname, dialIP, path, rawQuery)
	evidence := webobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(dialIP), input.Port).String(),
		TCPConnectMS:   1,
		HTTP: webobservation.HTTPObservation{
			Protocol: "HTTP/1.1", StatusCode: status, TTFBMS: 1, Location: location,
		},
	}
	if scheme == webobservation.SchemeHTTPS {
		evidence.TLS = &webobservation.TLSObservation{
			ServerName: hostname, Version: "TLS1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
			HandshakeMS: 1, VerifiedChains: 1,
			Leaf: webobservation.LeafCertificate{
				SHA256:    strings.Repeat("a", 64),
				NotBefore: testObservedAt().Add(-time.Hour),
				NotAfter:  testObservedAt().Add(time.Hour),
			},
		}
	}
	return webResult(probe.OutcomeSucceeded, input, &evidence, nil)
}

func webFailure(
	scheme webobservation.Scheme,
	hostname string,
	dialIP string,
	path string,
	code probe.FailureCode,
) webobservation.Result {
	return webResult(
		probe.OutcomeFailed,
		webInput(scheme, hostname, dialIP, path, ""),
		nil,
		&probe.Failure{Code: code, Detail: "scripted Web failure"},
	)
}

func webInput(
	scheme webobservation.Scheme,
	hostname string,
	dialIP string,
	path string,
	rawQuery string,
) webobservation.Input {
	parsed := netip.MustParseAddr(dialIP).Unmap()
	family := webobservation.FamilyIPv6
	if parsed.Is4() {
		family = webobservation.FamilyIPv4
	}
	port := uint16(443)
	if scheme == webobservation.SchemeHTTP {
		port = 80
	}
	return webobservation.Input{
		Scheme: scheme, Hostname: hostname, DialIP: parsed.String(), Family: family,
		Port: port, Method: "GET", Path: path, RawQuery: rawQuery,
	}
}

func webResult(
	outcome probe.Outcome,
	input webobservation.Input,
	evidence *webobservation.Evidence,
	failure *probe.Failure,
) webobservation.Result {
	return webobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindWebObservation,
		ObservedAt:    testObservedAt(),
		DurationMS:    4,
		Platform:      testPlatform(),
		Source:        testSource(),
		Input:         input,
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func testObservedAt() time.Time {
	return time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
}

func testPlatform() probe.Platform {
	return probe.Platform{OS: "testos", Arch: "testarch"}
}

func testSource() probe.Source {
	return probe.Source{Backend: "scripted", Capability: probe.CapabilityNative}
}

type resolverAdapter func(context.Context, string) systemresolver.Result

func (adapter resolverAdapter) Resolve(
	ctx context.Context,
	hostname string,
) systemresolver.Result {
	return adapter(ctx, hostname)
}

type webObserverAdapter func(context.Context, webobservation.Request) webobservation.Result

func (adapter webObserverAdapter) Observe(
	ctx context.Context,
	request webobservation.Request,
) webobservation.Result {
	return adapter(ctx, request)
}
