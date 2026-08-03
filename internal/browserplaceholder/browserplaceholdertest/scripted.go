// Package browserplaceholdertest supplies a deterministic Runner adapter for
// tests of Phase 0 browser-placeholder consumers.
package browserplaceholdertest

import (
	"context"
	"sync"

	"github.com/wangjc683/reachrun/internal/browserplaceholder"
)

// Step is one exact terminal result with an optional fallback notification.
type Step struct {
	Fallback *browserplaceholder.Fallback
	Result   browserplaceholder.Result
}

// Scripted returns a finite queue of steps. Exhaustion panics.
type Scripted struct {
	mu    sync.Mutex
	steps []Step
	calls int
}

var _ browserplaceholder.Runner = (*Scripted)(nil)

// New returns a scripted runner with defensive step copies.
func New(steps ...Step) *Scripted {
	copied := make([]Step, len(steps))
	for index, step := range steps {
		copied[index] = cloneStep(step)
	}
	return &Scripted{steps: copied}
}

// Run implements browserplaceholder.Runner.
func (s *Scripted) Run(
	_ context.Context,
	notify browserplaceholder.FallbackNotifier,
) browserplaceholder.Result {
	s.mu.Lock()
	if len(s.steps) == 0 {
		s.mu.Unlock()
		panic("browserplaceholdertest: unexpected Run call")
	}
	step := cloneStep(s.steps[0])
	s.steps = s.steps[1:]
	s.calls++
	s.mu.Unlock()
	if step.Fallback != nil {
		if err := notify(*step.Fallback); err != nil {
			panic("browserplaceholdertest: fallback notifier failed: " + err.Error())
		}
	}
	return cloneStep(step).Result
}

// Calls returns the number of Run calls.
func (s *Scripted) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Remaining returns the number of scripted steps not consumed.
func (s *Scripted) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.steps)
}

func cloneStep(step Step) Step {
	if step.Fallback != nil {
		fallback := *step.Fallback
		step.Fallback = &fallback
	}
	if step.Result.OpenAttempt != nil {
		attempt := *step.Result.OpenAttempt
		if attempt.Failure != nil {
			failure := *attempt.Failure
			attempt.Failure = &failure
		}
		step.Result.OpenAttempt = &attempt
	}
	if step.Result.PageRequest != nil {
		request := *step.Result.PageRequest
		step.Result.PageRequest = &request
	}
	return step
}
