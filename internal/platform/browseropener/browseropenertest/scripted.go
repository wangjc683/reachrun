// Package browseropenertest supplies a deterministic browser Opener adapter
// for tests of consumers at the platform browser-opening seam.
package browseropenertest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/platform/browseropener"
)

// Call records one exact URL passed to Open.
type Call struct {
	URL string
}

// Scripted returns a finite queue of exact results. Exhaustion panics so a
// consumer test cannot invent an unstated platform launch attempt.
type Scripted struct {
	mu      sync.Mutex
	results []browseropener.Result
	calls   []Call
}

var _ browseropener.Opener = (*Scripted)(nil)

// New returns a scripted adapter with defensive result copies.
func New(results ...browseropener.Result) *Scripted {
	copied := make([]browseropener.Result, len(results))
	for index, result := range results {
		copied[index] = cloneResult(result)
	}
	return &Scripted{results: copied}
}

// Open implements browseropener.Opener.
func (s *Scripted) Open(_ context.Context, rawURL string) browseropener.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, Call{URL: rawURL})
	if len(s.results) == 0 {
		panic("browseropenertest: unexpected Open call")
	}
	result := cloneResult(s.results[0])
	s.results = s.results[1:]
	return result
}

// Calls returns a defensive snapshot of all calls in order.
func (s *Scripted) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// Remaining returns the number of scripted results not consumed.
func (s *Scripted) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.results)
}

func cloneResult(result browseropener.Result) browseropener.Result {
	if result.Failure != nil {
		failure := *result.Failure
		result.Failure = &failure
	}
	return result
}
