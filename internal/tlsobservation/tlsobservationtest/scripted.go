// Package tlsobservationtest supplies the deterministic Observer adapter used
// by tests of hostname-free TLS-observation consumers.
package tlsobservationtest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

// Call records one request passed to a Scripted observer.
type Call struct {
	Request tlsobservation.Request
}

// Scripted returns a finite queue of exact evidence envelopes. Exhaustion
// panics so a test cannot silently manufacture unstated TLS evidence.
type Scripted struct {
	mu      sync.Mutex
	results []tlsobservation.Result
	calls   []Call
}

var _ tlsobservation.Observer = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...tlsobservation.Result) *Scripted {
	return &Scripted{results: append([]tlsobservation.Result(nil), results...)}
}

// Observe implements tlsobservation.Observer.
func (s *Scripted) Observe(
	_ context.Context,
	request tlsobservation.Request,
) tlsobservation.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{Request: request})
	if len(s.results) == 0 {
		panic("tlsobservationtest: unexpected Observe call")
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
