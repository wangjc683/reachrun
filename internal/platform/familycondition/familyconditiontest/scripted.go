// Package familyconditiontest supplies the deterministic Observer adapter used
// by tests of address-family-condition consumers.
package familyconditiontest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/platform/familycondition"
)

// Call records one Observe invocation.
type Call struct{}

// Scripted returns a finite queue of exact evidence envelopes. Exhaustion
// panics so a test cannot silently manufacture unstated platform evidence.
type Scripted struct {
	mu      sync.Mutex
	results []familycondition.Result
	calls   []Call
}

var _ familycondition.Observer = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...familycondition.Result) *Scripted {
	return &Scripted{results: append([]familycondition.Result(nil), results...)}
}

// Observe implements familycondition.Observer.
func (s *Scripted) Observe(context.Context) familycondition.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{})
	if len(s.results) == 0 {
		panic("familyconditiontest: unexpected Observe call")
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result
}

// Calls returns a snapshot of Observe calls in order.
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
