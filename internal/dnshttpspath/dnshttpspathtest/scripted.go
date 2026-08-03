// Package dnshttpspathtest supplies the deterministic Observer adapter used by
// tests of DNS HTTPS-path consumers.
package dnshttpspathtest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/dnshttpspath"
)

// Call records one request passed to a Scripted observer.
type Call struct {
	Request dnshttpspath.Request
}

// Scripted returns a finite queue of exact aggregate reports. Exhaustion
// panics so tests cannot manufacture unstated path evidence.
type Scripted struct {
	mu      sync.Mutex
	results []dnshttpspath.Result
	calls   []Call
}

var _ dnshttpspath.Observer = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...dnshttpspath.Result) *Scripted {
	return &Scripted{results: append([]dnshttpspath.Result(nil), results...)}
}

// Observe implements dnshttpspath.Observer.
func (s *Scripted) Observe(_ context.Context, request dnshttpspath.Request) dnshttpspath.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{Request: request})
	if len(s.results) == 0 {
		panic("dnshttpspathtest: unexpected Observe call")
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result
}

// Calls returns a snapshot of all calls in order.
func (s *Scripted) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// Remaining returns the number of queued reports.
func (s *Scripted) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}
