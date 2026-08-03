// Package webrechecktest supplies the deterministic Observer adapter used by
// tests of Web-candidate-recheck consumers.
package webrechecktest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/webrecheck"
)

// Call records one request passed to a Scripted observer.
type Call struct {
	Request webrecheck.Request
}

// Scripted returns a finite queue of exact aggregate reports. Exhaustion
// panics so consumer tests cannot silently manufacture unstated evidence.
type Scripted struct {
	mu      sync.Mutex
	results []webrecheck.Result
	calls   []Call
}

var _ webrecheck.Observer = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...webrecheck.Result) *Scripted {
	return &Scripted{results: append([]webrecheck.Result(nil), results...)}
}

// Observe implements webrecheck.Observer.
func (s *Scripted) Observe(_ context.Context, request webrecheck.Request) webrecheck.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{Request: cloneRequest(request)})
	if len(s.results) == 0 {
		panic("webrechecktest: unexpected Observe call")
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result
}

// Calls returns a snapshot of all calls in order.
func (s *Scripted) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]Call, len(s.calls))
	for index, call := range s.calls {
		result[index] = Call{Request: cloneRequest(call.Request)}
	}
	return result
}

// Remaining returns the number of scripted results not yet consumed.
func (s *Scripted) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}

func cloneRequest(request webrecheck.Request) webrecheck.Request {
	request.LocalCandidates = append([]string(nil), request.LocalCandidates...)
	request.ReferenceCandidates = append([]string(nil), request.ReferenceCandidates...)
	return request
}
