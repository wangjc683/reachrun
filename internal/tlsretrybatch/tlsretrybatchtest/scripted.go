// Package tlsretrybatchtest supplies the deterministic Observer adapter used
// by tests of TLS retry-batch consumers.
package tlsretrybatchtest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/tlsretrybatch"
)

// Call records one request passed to a Scripted observer.
type Call struct {
	Request tlsretrybatch.Request
}

// Scripted returns a finite queue of exact reports. Exhaustion panics so a
// consumer test cannot manufacture unstated retry or cancellation evidence.
type Scripted struct {
	mu      sync.Mutex
	results []tlsretrybatch.Result
	calls   []Call
}

var _ tlsretrybatch.Observer = (*Scripted)(nil)

// New returns a scripted adapter with defensive copies of results.
func New(results ...tlsretrybatch.Result) *Scripted {
	return &Scripted{results: append([]tlsretrybatch.Result(nil), results...)}
}

// Observe implements tlsretrybatch.Observer.
func (s *Scripted) Observe(
	_ context.Context,
	request tlsretrybatch.Request,
) tlsretrybatch.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	request.Targets = append([]string(nil), request.Targets...)
	s.calls = append(s.calls, Call{Request: request})
	if len(s.results) == 0 {
		panic("tlsretrybatchtest: unexpected Observe call")
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result
}

// Calls returns a defensive snapshot of all calls in order.
func (s *Scripted) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Call, len(s.calls))
	for index, call := range s.calls {
		call.Request.Targets = append([]string(nil), call.Request.Targets...)
		result[index] = call
	}
	return result
}

// Remaining returns the number of scripted reports not consumed.
func (s *Scripted) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}
