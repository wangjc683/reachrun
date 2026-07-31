// Package resolverinventorytest supplies deterministic Resolver Inventory
// adapters for tests of callers.
package resolverinventorytest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/platform/resolverinventory"
)

// Call records one Observe invocation.
type Call struct{}

// Scripted returns a finite queue of exact resolver-inventory envelopes.
// Exhausting the queue panics so tests cannot manufacture unstated evidence.
type Scripted struct {
	mu      sync.Mutex
	results []resolverinventory.Result
	calls   []Call
}

var _ resolverinventory.Observer = (*Scripted)(nil)

// New returns a scripted adapter with a defensive copy of results.
func New(results ...resolverinventory.Result) *Scripted {
	return &Scripted{results: append([]resolverinventory.Result(nil), results...)}
}

// Observe implements resolverinventory.Observer.
func (s *Scripted) Observe(context.Context) resolverinventory.Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, Call{})
	if len(s.results) == 0 {
		panic("resolverinventorytest: unexpected Observe call")
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
