// Package sshobservationtest supplies the deterministic Observer adapter used
// by tests of SSH-observation consumers.
package sshobservationtest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/sshobservation"
)

// Call records one request passed to a Scripted observer.
type Call struct {
	Request sshobservation.Request
}

// Scripted returns a finite queue of exact evidence envelopes. Exhaustion
// panics so a test cannot silently manufacture unstated SSH evidence.
type Scripted struct {
	mu      sync.Mutex
	results []sshobservation.Result
	calls   []Call
}

var _ sshobservation.Observer = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...sshobservation.Result) *Scripted {
	return &Scripted{results: append([]sshobservation.Result(nil), results...)}
}

// Observe implements sshobservation.Observer.
func (s *Scripted) Observe(
	_ context.Context,
	request sshobservation.Request,
) sshobservation.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{Request: request})
	if len(s.results) == 0 {
		panic("sshobservationtest: unexpected Observe call")
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
