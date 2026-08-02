// Package webpathtest supplies the deterministic Observer adapter used by
// tests of public-Web-path consumers.
package webpathtest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/webpath"
)

// Call records one request passed to a Scripted observer.
type Call struct {
	Request webpath.Request
}

// Scripted returns a finite queue of exact aggregate reports. Exhaustion
// panics so consumer tests cannot silently manufacture unstated path evidence.
type Scripted struct {
	mu      sync.Mutex
	results []webpath.Result
	calls   []Call
}

var _ webpath.Observer = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...webpath.Result) *Scripted {
	return &Scripted{results: append([]webpath.Result(nil), results...)}
}

// Observe implements webpath.Observer.
func (s *Scripted) Observe(_ context.Context, request webpath.Request) webpath.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{Request: request})
	if len(s.results) == 0 {
		panic("webpathtest: unexpected Observe call")
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

// Remaining returns the number of scripted results not yet consumed.
func (s *Scripted) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}
