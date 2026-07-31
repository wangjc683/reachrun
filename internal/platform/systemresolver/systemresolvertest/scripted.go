// Package systemresolvertest supplies the deterministic Resolver adapter used
// by tests of consumers such as the Phase 0 CLI.
package systemresolvertest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
)

// Call records one hostname passed to a Scripted resolver.
type Call struct {
	Hostname string
}

// Scripted returns a finite queue of exact evidence envelopes. Exhausting the
// queue panics so tests cannot accidentally manufacture unstated evidence.
type Scripted struct {
	mu      sync.Mutex
	results []systemresolver.Result
	calls   []Call
}

var _ systemresolver.Resolver = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...systemresolver.Result) *Scripted {
	return &Scripted{
		results: append([]systemresolver.Result(nil), results...),
	}
}

// Resolve implements systemresolver.Resolver.
func (s *Scripted) Resolve(_ context.Context, hostname string) systemresolver.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{Hostname: hostname})
	if len(s.results) == 0 {
		panic("systemresolvertest: unexpected Resolve call")
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
