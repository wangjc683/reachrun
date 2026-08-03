package dnsobservation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"golang.org/x/net/dns/dnsmessage"
)

func TestObserveUDPReturnsOrderedTypedAnswers(t *testing.T) {
	t.Parallel()

	port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
		request, err := unpackDNSMessage(query)
		if err != nil {
			return nil, err
		}
		if request.Header.ID != 0x1234 || !request.Header.RecursionDesired {
			return nil, fmt.Errorf("query header = %#v, want id 0x1234 with RD", request.Header)
		}
		if len(request.Questions) != 1 ||
			request.Questions[0].Name.String() != "www.example.com." ||
			request.Questions[0].Type != dnsmessage.TypeA ||
			request.Questions[0].Class != dnsmessage.ClassINET {
			return nil, fmt.Errorf("unexpected query questions: %#v", request.Questions)
		}
		return packResponse(query, func(response *dnsmessage.Message) {
			response.Header.Authoritative = true
			response.Answers = []dnsmessage.Resource{
				cnameResource("www.example.com.", "edge.example.net.", 60),
				aResource("edge.example.net.", [4]byte{192, 0, 2, 10}, 30),
			}
		})
	})
	observer := newTestWireObserver(t, port, time.Second)

	result := observer.Observe(context.Background(), Request{
		Hostname:  " WWW.Example.COM. ",
		QueryType: QueryTypeA,
		Resolver:  "wire-test",
		Transport: TransportUDP,
	})
	waitResponder(t, done)

	assertValidSuccess(t, result)
	if result.Input.Hostname != "www.example.com" {
		t.Fatalf("normalized hostname = %q, want www.example.com", result.Input.Hostname)
	}
	if result.Input.Resolver.Endpoint != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String() {
		t.Fatalf("input endpoint = %q, want configured test endpoint", result.Input.Resolver.Endpoint)
	}
	if result.Evidence.AnswerKind != AnswerKindAnswer || result.Evidence.EffectiveName != "edge.example.net" {
		t.Fatalf("classification = %q/%q, want answer/edge.example.net", result.Evidence.AnswerKind, result.Evidence.EffectiveName)
	}
	wantRecords := []Record{
		{Name: "www.example.com", Type: QueryTypeCNAME, TTL: 60, Target: "edge.example.net"},
		{Name: "edge.example.net", Type: QueryTypeA, TTL: 30, Address: "192.0.2.10", Family: IPFamilyIPv4},
	}
	if !reflect.DeepEqual(result.Evidence.Records, wantRecords) {
		t.Fatalf("records = %#v, want wire-ordered %#v", result.Evidence.Records, wantRecords)
	}
	if !result.Evidence.Flags.Authoritative || !result.Evidence.Flags.RecursionDesired ||
		!result.Evidence.Flags.RecursionAvailable {
		t.Fatalf("flags = %#v, want AA/RD/RA", result.Evidence.Flags)
	}
	remote, err := netip.ParseAddrPort(result.Evidence.RemoteEndpoint)
	if err != nil || remote.Port() != port || remote.Addr().String() != "127.0.0.1" {
		t.Fatalf("remote endpoint = %q, want 127.0.0.1:%d", result.Evidence.RemoteEndpoint, port)
	}
}

func TestObserveUDPDoesNotFallbackWhenTruncated(t *testing.T) {
	t.Parallel()

	port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
		return packResponse(query, func(response *dnsmessage.Message) {
			response.Header.Truncated = true
		})
	})
	observer := newTestWireObserver(t, port, time.Second)

	result := observer.Observe(context.Background(), wireRequest(QueryTypeA, TransportUDP))
	waitResponder(t, done)

	assertValidSuccess(t, result)
	if result.Evidence.AnswerKind != AnswerKindIncomplete || !result.Evidence.Flags.Truncated {
		t.Fatalf("evidence = %#v, want a successful incomplete UDP response", result.Evidence)
	}
}

func TestObserveTCPUsesLengthFramingAndReturnsAAAA(t *testing.T) {
	t.Parallel()

	port, done := startTCPResponder(t, func(query []byte) ([]byte, error) {
		request, err := unpackDNSMessage(query)
		if err != nil {
			return nil, err
		}
		if request.Header.ID != 0x1234 || len(request.Questions) != 1 || request.Questions[0].Type != dnsmessage.TypeAAAA {
			return nil, fmt.Errorf("unexpected TCP query: %#v", request)
		}
		return packResponse(query, func(response *dnsmessage.Message) {
			response.Answers = []dnsmessage.Resource{
				aaaaResource("www.example.com.", [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}, 120),
			}
		})
	})
	observer := newTestWireObserver(t, port, time.Second)

	result := observer.Observe(context.Background(), wireRequest(QueryTypeAAAA, TransportTCP))
	waitResponder(t, done)

	assertValidSuccess(t, result)
	want := []Record{{
		Name:    "www.example.com",
		Type:    QueryTypeAAAA,
		TTL:     120,
		Address: "2001:db8::10",
		Family:  IPFamilyIPv6,
	}}
	if !reflect.DeepEqual(result.Evidence.Records, want) {
		t.Fatalf("records = %#v, want %#v", result.Evidence.Records, want)
	}
}

func TestObserveSupportsCNAMEQuestion(t *testing.T) {
	t.Parallel()

	port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
		request, err := unpackDNSMessage(query)
		if err != nil {
			return nil, err
		}
		if request.Questions[0].Type != dnsmessage.TypeCNAME {
			return nil, fmt.Errorf("query type = %v, want CNAME", request.Questions[0].Type)
		}
		return packResponse(query, func(response *dnsmessage.Message) {
			response.Answers = []dnsmessage.Resource{
				cnameResource("www.example.com.", "edge.example.net.", 60),
			}
		})
	})
	observer := newTestWireObserver(t, port, time.Second)

	result := observer.Observe(context.Background(), wireRequest(QueryTypeCNAME, TransportUDP))
	waitResponder(t, done)

	assertValidSuccess(t, result)
	if result.Evidence.AnswerKind != AnswerKindAnswer || result.Evidence.EffectiveName != "edge.example.net" {
		t.Fatalf("CNAME result = %#v, want answer at original name and effective target", result.Evidence)
	}
}

func TestObserveReturnsTypedHTTPSAndSVCBRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		queryType QueryType
		wireType  dnsmessage.Type
		resource  dnsmessage.Resource
		want      Record
	}{
		{
			name:      "HTTPS ServiceMode",
			queryType: QueryTypeHTTPS,
			wireType:  dnsmessage.TypeHTTPS,
			resource: serviceResource(
				QueryTypeHTTPS,
				"www.example.com.",
				1,
				"svc.example.net.",
				[]dnsmessage.SVCParam{
					{Key: dnsmessage.SVCParamMandatory, Value: []byte{0, 1}},
					{Key: dnsmessage.SVCParamALPN, Value: []byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}},
					{Key: dnsmessage.SVCParamPort, Value: []byte{0x01, 0xbb}},
					{Key: dnsmessage.SVCParamIPv4Hint, Value: []byte{192, 0, 2, 1}},
				},
			),
			want: Record{
				Name: "www.example.com", Type: QueryTypeHTTPS, TTL: 300,
				Service: &ServiceBinding{
					Priority: 1, Target: "svc.example.net", Mode: ServiceBindingService,
					Params: []ServiceParameter{
						{Key: 0, Name: "mandatory", ValueHex: "0001"},
						{Key: 1, Name: "alpn", ValueHex: "02683208687474702f312e31"},
						{Key: 3, Name: "port", ValueHex: "01bb"},
						{Key: 4, Name: "ipv4hint", ValueHex: "c0000201"},
					},
				},
			},
		},
		{
			name:      "SVCB AliasMode",
			queryType: QueryTypeSVCB,
			wireType:  dnsmessage.TypeSVCB,
			resource: serviceResource(
				QueryTypeSVCB,
				"www.example.com.",
				0,
				"alias.example.net.",
				nil,
			),
			want: Record{
				Name: "www.example.com", Type: QueryTypeSVCB, TTL: 300,
				Service: &ServiceBinding{
					Priority: 0, Target: "alias.example.net", Mode: ServiceBindingAlias,
					Params: []ServiceParameter{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
				request, err := unpackDNSMessage(query)
				if err != nil {
					return nil, err
				}
				if len(request.Questions) != 1 || request.Questions[0].Type != test.wireType {
					return nil, fmt.Errorf("query = %#v, want type %v", request.Questions, test.wireType)
				}
				return packResponse(query, func(response *dnsmessage.Message) {
					response.Answers = []dnsmessage.Resource{test.resource}
				})
			})
			observer := newTestWireObserver(t, port, time.Second)

			result := observer.Observe(context.Background(), wireRequest(test.queryType, TransportUDP))
			waitResponder(t, done)

			assertValidSuccess(t, result)
			if result.Evidence.AnswerKind != AnswerKindAnswer ||
				!reflect.DeepEqual(result.Evidence.Records, []Record{test.want}) {
				t.Fatalf("HTTPS/SVCB evidence = %#v, want record %#v", result.Evidence, test.want)
			}
		})
	}
}

func TestObserveClassifiesValidDNSOutcomesAsSucceeded(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*dnsmessage.Message)
		kind    AnswerKind
		rcode   string
		wantSOA bool
		wantNS  bool
	}{
		"nxdomain": {
			mutate: func(response *dnsmessage.Message) {
				response.Header.RCode = dnsmessage.RCodeNameError
				response.Authorities = []dnsmessage.Resource{soaResource("example.com.")}
			},
			kind: AnswerKindNameError, rcode: "NXDOMAIN", wantSOA: true,
		},
		"nodata": {
			mutate: func(response *dnsmessage.Message) {
				response.Authorities = []dnsmessage.Resource{soaResource("example.com.")}
			},
			kind: AnswerKindNoData, rcode: "NOERROR", wantSOA: true,
		},
		"referral": {
			mutate: func(response *dnsmessage.Message) {
				response.Authorities = []dnsmessage.Resource{
					nsResource("example.com.", "ns1.example.net.", 300),
					nsResource("example.com.", "ns2.example.net.", 200),
				}
			},
			kind: AnswerKindReferral, rcode: "NOERROR", wantNS: true,
		},
		"servfail": {
			mutate: func(response *dnsmessage.Message) {
				response.Header.RCode = dnsmessage.RCodeServerFailure
			},
			kind: AnswerKindRCodeError, rcode: "SERVFAIL",
		},
		"refused": {
			mutate: func(response *dnsmessage.Message) {
				response.Header.RCode = dnsmessage.RCodeRefused
			},
			kind: AnswerKindRCodeError, rcode: "REFUSED",
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
				return packResponse(query, test.mutate)
			})
			observer := newTestWireObserver(t, port, time.Second)

			result := observer.Observe(context.Background(), wireRequest(QueryTypeA, TransportUDP))
			waitResponder(t, done)

			assertValidSuccess(t, result)
			if result.Evidence.AnswerKind != test.kind || result.Evidence.RCode.Name != test.rcode {
				t.Fatalf("classification = %q/%q, want %q/%q", result.Evidence.AnswerKind, result.Evidence.RCode.Name, test.kind, test.rcode)
			}
			if (result.Evidence.NegativeSOA != nil) != test.wantSOA {
				t.Fatalf("negative SOA present = %v, want %v", result.Evidence.NegativeSOA != nil, test.wantSOA)
			}
			if (len(result.Evidence.AuthorityNS) > 0) != test.wantNS {
				t.Fatalf("authority NS = %#v, want present %v", result.Evidence.AuthorityNS, test.wantNS)
			}
			if test.wantNS {
				want := []NSRecord{
					{Name: "example.com", TTL: 300, Target: "ns1.example.net"},
					{Name: "example.com", TTL: 200, Target: "ns2.example.net"},
				}
				if !reflect.DeepEqual(result.Evidence.AuthorityNS, want) {
					t.Fatalf("authority NS = %#v, want wire-ordered %#v", result.Evidence.AuthorityNS, want)
				}
			}
		})
	}
}

func TestObserveRejectsInvalidDNSResponseIdentity(t *testing.T) {
	t.Parallel()

	tests := map[string]func([]byte) ([]byte, error){
		"qr is false": func(query []byte) ([]byte, error) {
			return packResponse(query, func(response *dnsmessage.Message) {
				response.Header.Response = false
			})
		},
		"id mismatch": func(query []byte) ([]byte, error) {
			return packResponse(query, func(response *dnsmessage.Message) {
				response.Header.ID++
			})
		},
		"question mismatch": func(query []byte) ([]byte, error) {
			return packResponse(query, func(response *dnsmessage.Message) {
				response.Questions[0].Name = dnsmessage.MustNewName("other.example.")
			})
		},
		"malformed body": func([]byte) ([]byte, error) {
			return []byte{0x12, 0x34, 0x80}, nil
		},
	}

	for name, responder := range tests {
		name, responder := name, responder
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			port, done := startUDPResponder(t, responder)
			observer := newTestWireObserver(t, port, time.Second)

			result := observer.Observe(context.Background(), wireRequest(QueryTypeA, TransportUDP))
			waitResponder(t, done)

			assertFailure(t, result, probe.OutcomeFailed, FailureDNSProtocol)
		})
	}
}

func TestObserveRejectsResponseRecordOverflow(t *testing.T) {
	t.Parallel()

	port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
		return packResponse(query, func(response *dnsmessage.Message) {
			response.Answers = make([]dnsmessage.Resource, maxResponseRecords+1)
			for index := range response.Answers {
				response.Answers[index] = aResource(
					"www.example.com.",
					[4]byte{192, 0, byte(index / 250), byte(index%250 + 1)},
					60,
				)
			}
		})
	})
	observer := newTestWireObserver(t, port, time.Second)

	result := observer.Observe(context.Background(), wireRequest(QueryTypeA, TransportUDP))
	waitResponder(t, done)

	assertFailure(t, result, probe.OutcomeFailed, FailureDNSProtocol)
}

func TestObserveNormalizesTimeout(t *testing.T) {
	port, done := startUDPResponder(t, func([]byte) ([]byte, error) {
		return nil, nil
	})
	observer := newTestWireObserver(t, port, 30*time.Millisecond)

	result := observer.Observe(context.Background(), wireRequest(QueryTypeA, TransportUDP))
	waitResponder(t, done)

	assertFailure(t, result, probe.OutcomeFailed, probe.FailureTimeout)
}

func TestObserveDiscardsResponseAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
		response, err := packResponse(query, func(response *dnsmessage.Message) {
			response.Answers = []dnsmessage.Resource{
				aResource("www.example.com.", [4]byte{192, 0, 2, 10}, 60),
			}
		})
		cancel()
		return response, err
	})
	observer := newTestWireObserver(t, port, time.Second)

	result := observer.Observe(ctx, wireRequest(QueryTypeA, TransportUDP))
	waitResponder(t, done)

	assertFailure(t, result, probe.OutcomeCancelled, probe.FailureCancelled)
	if result.Evidence != nil {
		t.Fatalf("evidence = %#v, want nil after cancellation", result.Evidence)
	}
}

func TestObserveChecksCancellationAtSuccessCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port, done := startUDPResponder(t, func(query []byte) ([]byte, error) {
		return packResponse(query, func(response *dnsmessage.Message) {
			response.Answers = []dnsmessage.Resource{
				aResource("www.example.com.", [4]byte{192, 0, 2, 10}, 60),
			}
		})
	})
	observer, err := newObserver(Config{
		Resolvers: []ResolverEndpoint{{ID: "wire-test", WireIP: netip.MustParseAddr("127.0.0.1")}},
		Timeout:   time.Second,
	}, dependencies{
		now:                 time.Now,
		random:              bytes.NewReader([]byte{0x12, 0x34}),
		wirePort:            port,
		beforeSuccessCommit: cancel,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}

	result := observer.Observe(ctx, wireRequest(QueryTypeA, TransportUDP))
	waitResponder(t, done)

	assertFailure(t, result, probe.OutcomeCancelled, probe.FailureCancelled)
	if result.Evidence != nil {
		t.Fatalf("evidence = %#v, want nil when cancellation wins at commit", result.Evidence)
	}
}

func TestObserveDoHUsesPOSTAndFixedBootstrap(t *testing.T) {
	t.Parallel()

	requestChecks := make(chan error, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			requestChecks <- err
			http.Error(writer, "read", http.StatusInternalServerError)
			return
		}
		message, err := unpackDNSMessage(body)
		if err == nil {
			switch {
			case request.Method != http.MethodPost:
				err = fmt.Errorf("method = %s, want POST", request.Method)
			case request.URL.Path != "/dns-query":
				err = fmt.Errorf("path = %s, want /dns-query", request.URL.Path)
			case request.Header.Get("Content-Type") != "application/dns-message":
				err = fmt.Errorf("content type = %q", request.Header.Get("Content-Type"))
			case request.Header.Get("Accept") != "application/dns-message":
				err = fmt.Errorf("accept = %q", request.Header.Get("Accept"))
			case message.Header.ID != 0:
				err = fmt.Errorf("DoH DNS id = %d, want 0", message.Header.ID)
			case len(message.Questions) != 1 || message.Questions[0].Type != dnsmessage.TypeA:
				err = fmt.Errorf("unexpected DoH question: %#v", message.Questions)
			}
		}
		requestChecks <- err
		response, packErr := packResponse(body, func(response *dnsmessage.Message) {
			response.Answers = []dnsmessage.Resource{
				aResource("www.example.com.", [4]byte{192, 0, 2, 20}, 60),
			}
		})
		if packErr != nil {
			http.Error(writer, packErr.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message; charset=binary")
		_, _ = writer.Write(response)
	}))
	defer server.Close()
	observer, bootstrap := newTestDoHObserver(t, server, time.Second)

	result := observer.Observe(context.Background(), Request{
		Hostname:  "www.example.com",
		QueryType: QueryTypeA,
		Resolver:  "doh-test",
		Transport: TransportDoH,
	})

	if err := <-requestChecks; err != nil {
		t.Fatalf("DoH request contract: %v", err)
	}
	assertValidSuccess(t, result)
	if result.Evidence.DoHStatus != http.StatusOK || result.Evidence.RemoteEndpoint != bootstrap {
		t.Fatalf("DoH endpoint/status = %q/%d, want %q/200", result.Evidence.RemoteEndpoint, result.Evidence.DoHStatus, bootstrap)
	}
	if result.Input.Resolver.Endpoint != testDoHURL(t, server) {
		t.Fatalf("input resolver endpoint = %q, want configured DoH URL", result.Input.Resolver.Endpoint)
	}
}

func TestObserveDoHEnforcesHTTPRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		handler func(http.ResponseWriter, *http.Request)
		code    probe.FailureCode
	}{
		"non 2xx": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			},
			code: FailureDoHRule,
		},
		"wrong content type": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "text/plain")
				_, _ = writer.Write([]byte("not dns"))
			},
			code: FailureDoHRule,
		},
		"oversized body": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/dns-message")
				_, _ = writer.Write(bytes.Repeat([]byte{0}, maxDNSMessageBytes+1))
			},
			code: FailureDoHRule,
		},
		"malformed dns": {
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/dns-message")
				_, _ = writer.Write([]byte{0, 1, 2})
			},
			code: FailureDNSProtocol,
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(test.handler))
			defer server.Close()
			observer, _ := newTestDoHObserver(t, server, time.Second)

			result := observer.Observe(context.Background(), Request{
				Hostname: "www.example.com", QueryType: QueryTypeA,
				Resolver: "doh-test", Transport: TransportDoH,
			})

			assertFailure(t, result, probe.OutcomeFailed, test.code)
		})
	}
}

func TestObserveDoHDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()

	var redirected atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected.Add(1)
			writer.Header().Set("Content-Type", "application/dns-message")
			return
		}
		http.Redirect(writer, request, "/redirected", http.StatusFound)
	}))
	defer server.Close()
	observer, _ := newTestDoHObserver(t, server, time.Second)

	result := observer.Observe(context.Background(), Request{
		Hostname: "www.example.com", QueryType: QueryTypeA,
		Resolver: "doh-test", Transport: TransportDoH,
	})

	assertFailure(t, result, probe.OutcomeFailed, FailureDoHRule)
	if redirected.Load() != 0 {
		t.Fatalf("redirect target received %d requests, want 0", redirected.Load())
	}
}

func TestObserveRejectsInvalidRequestBeforeNetwork(t *testing.T) {
	t.Parallel()

	observer, err := newObserver(Config{Resolvers: []ResolverEndpoint{{
		ID: "wire-test", WireIP: netip.MustParseAddr("127.0.0.1"),
	}}}, dependencies{
		now:      time.Now,
		random:   bytes.NewReader([]byte{0x12, 0x34}),
		wirePort: 1,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}

	tests := []Request{
		{Hostname: "", QueryType: QueryTypeA, Resolver: "wire-test", Transport: TransportUDP},
		{Hostname: "192.0.2.1", QueryType: QueryTypeA, Resolver: "wire-test", Transport: TransportUDP},
		{Hostname: "https://example.com", QueryType: QueryTypeA, Resolver: "wire-test", Transport: TransportUDP},
		{Hostname: "example.com", QueryType: "MX", Resolver: "wire-test", Transport: TransportUDP},
		{Hostname: "example.com", QueryType: QueryTypeA, Resolver: "missing", Transport: TransportUDP},
		{Hostname: "example.com", QueryType: QueryTypeA, Resolver: "wire-test", Transport: "tls"},
	}
	for _, request := range tests {
		result := observer.Observe(context.Background(), request)
		assertFailure(t, result, probe.OutcomeFailed, probe.FailureInvalidInput)
	}
}

func TestObserveCancellationWinsBeforeResolverLookup(t *testing.T) {
	t.Parallel()

	observer, err := newObserver(Config{Resolvers: []ResolverEndpoint{{
		ID: "wire-test", WireIP: netip.MustParseAddr("127.0.0.1"),
	}}}, dependencies{
		now:      time.Now,
		random:   bytes.NewReader([]byte{0x12, 0x34}),
		wirePort: 1,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := observer.Observe(ctx, Request{
		Hostname:  "example.com",
		QueryType: QueryTypeA,
		Resolver:  "missing-after-cancel",
		Transport: TransportUDP,
	})

	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	assertFailure(t, result, probe.OutcomeCancelled, probe.FailureCancelled)
}

type responderFunc func([]byte) ([]byte, error)

func startUDPResponder(t *testing.T, responder responderFunc) (uint16, <-chan error) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	done := make(chan error, 1)
	go func() {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, maxDNSMessageBytes)
		n, remote, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			done <- readErr
			return
		}
		response, responseErr := responder(append([]byte(nil), buffer[:n]...))
		if responseErr != nil {
			done <- responseErr
			return
		}
		if response != nil {
			_, responseErr = conn.WriteToUDP(response, remote)
		}
		done <- responseErr
	}()
	return port, done
}

func startTCPResponder(t *testing.T, responder responderFunc) (uint16, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var length [2]byte
		if _, readErr := io.ReadFull(conn, length[:]); readErr != nil {
			done <- readErr
			return
		}
		queryLength := int(binary.BigEndian.Uint16(length[:]))
		if queryLength == 0 {
			done <- errors.New("received zero-length TCP DNS query")
			return
		}
		query := make([]byte, queryLength)
		if _, readErr := io.ReadFull(conn, query); readErr != nil {
			done <- readErr
			return
		}
		response, responseErr := responder(query)
		if responseErr != nil {
			done <- responseErr
			return
		}
		if response != nil {
			framed := make([]byte, 2+len(response))
			binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
			copy(framed[2:], response)
			responseErr = writeAll(conn, framed)
		}
		done <- responseErr
	}()
	return port, done
}

func waitResponder(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("local DNS responder: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("local DNS responder did not finish")
	}
}

func newTestWireObserver(t *testing.T, port uint16, timeout time.Duration) *observer {
	t.Helper()
	created, err := newObserver(Config{
		Resolvers: []ResolverEndpoint{{ID: "wire-test", WireIP: netip.MustParseAddr("127.0.0.1")}},
		Timeout:   timeout,
	}, dependencies{
		now:      time.Now,
		random:   bytes.NewReader([]byte{0x12, 0x34}),
		wirePort: port,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	return created
}

func newTestDoHObserver(t *testing.T, server *httptest.Server, timeout time.Duration) (*observer, string) {
	t.Helper()
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(server.Certificate())
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	bootstrap, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("parse test server bootstrap: %v", err)
	}
	created, err := newObserver(Config{
		Resolvers: []ResolverEndpoint{{
			ID:           "doh-test",
			DoHURL:       testDoHURL(t, server),
			DoHBootstrap: bootstrap,
		}},
		Timeout: timeout,
	}, dependencies{
		now:     time.Now,
		random:  bytes.NewReader([]byte{0x12, 0x34}),
		rootCAs: rootCAs,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	return created, net.JoinHostPort(bootstrap.String(), port)
}

func testDoHURL(t *testing.T, server *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test DoH server address: %v", err)
	}
	// httptest's certificate covers *.example.com. Deliberately keep the URL
	// hostname different from the listener IP so the protocol test proves that
	// dialing uses the configured bootstrap address while TLS uses the URL name.
	return "https://dns.example.com:" + port + "/dns-query"
}

func wireRequest(queryType QueryType, transport Transport) Request {
	return Request{
		Hostname:  "www.example.com",
		QueryType: queryType,
		Resolver:  "wire-test",
		Transport: transport,
	}
}

func unpackDNSMessage(raw []byte) (dnsmessage.Message, error) {
	var message dnsmessage.Message
	if err := message.Unpack(raw); err != nil {
		return dnsmessage.Message{}, fmt.Errorf("unpack DNS message: %w", err)
	}
	return message, nil
}

func packResponse(query []byte, mutate func(*dnsmessage.Message)) ([]byte, error) {
	request, err := unpackDNSMessage(query)
	if err != nil {
		return nil, err
	}
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 request.Header.ID,
			Response:           true,
			RecursionDesired:   request.Header.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: append([]dnsmessage.Question(nil), request.Questions...),
	}
	if mutate != nil {
		mutate(&response)
	}
	packed, err := response.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS response: %w", err)
	}
	return packed, nil
}

func aResource(name string, address [4]byte, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA,
			Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.AResource{A: address},
	}
}

func aaaaResource(name string, address [16]byte, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.AAAAResource{AAAA: address},
	}
}

func cnameResource(name, target string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

func serviceResource(
	recordType QueryType,
	name string,
	priority uint16,
	target string,
	params []dnsmessage.SVCParam,
) dnsmessage.Resource {
	header := dnsmessage.ResourceHeader{
		Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: 300,
	}
	service := dnsmessage.SVCBResource{
		Priority: priority,
		Target:   dnsmessage.MustNewName(target),
		Params:   params,
	}
	switch recordType {
	case QueryTypeSVCB:
		header.Type = dnsmessage.TypeSVCB
		return dnsmessage.Resource{Header: header, Body: &service}
	case QueryTypeHTTPS:
		header.Type = dnsmessage.TypeHTTPS
		return dnsmessage.Resource{
			Header: header,
			Body:   &dnsmessage.HTTPSResource{SVCBResource: service},
		}
	default:
		panic("serviceResource requires SVCB or HTTPS")
	}
}

func nsResource(name, target string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeNS,
			Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName(target)},
	}
}

func soaResource(name string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeSOA,
			Class: dnsmessage.ClassINET, TTL: 300,
		},
		Body: &dnsmessage.SOAResource{
			NS:      dnsmessage.MustNewName("ns1.example.net."),
			MBox:    dnsmessage.MustNewName("hostmaster.example.com."),
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			MinTTL:  300,
		},
	}
}

func assertValidSuccess(t *testing.T, result Result) {
	t.Helper()
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != probe.OutcomeSucceeded || result.Evidence == nil || result.Failure != nil {
		t.Fatalf("terminal result = %#v, want succeeded evidence", result)
	}
}

func assertFailure(t *testing.T, result Result, outcome probe.Outcome, code probe.FailureCode) {
	t.Helper()
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Outcome != outcome || result.Failure == nil || result.Failure.Code != code {
		t.Fatalf("terminal result = %#v, want outcome %q failure %q", result, outcome, code)
	}
	if result.Evidence != nil {
		t.Fatalf("failure evidence = %#v, want nil", result.Evidence)
	}
	if strings.TrimSpace(result.Failure.Detail) == "" {
		t.Fatal("failure detail is empty")
	}
}
