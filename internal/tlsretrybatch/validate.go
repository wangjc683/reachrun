package tlsretrybatch

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

// Validate checks the aggregate contract, fixed retry schedule, and every
// embedded TLS Observation envelope.
func Validate(result Result) error {
	if result.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if result.Operation != Operation {
		return fmt.Errorf("operation must be %q", Operation)
	}
	if result.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at must not be zero")
	}
	if _, offset := result.ObservedAt.Zone(); offset != 0 {
		return fmt.Errorf("observed_at must use UTC")
	}
	if result.DurationMS < 0 {
		return fmt.Errorf("duration_ms must not be negative")
	}
	if result.Platform.OS == "" || result.Platform.Arch == "" {
		return fmt.Errorf("platform must include OS and architecture")
	}
	if result.Input.Targets == nil || result.Targets == nil {
		return fmt.Errorf("input targets and target results must encode as arrays")
	}

	normalized, inputErr := normalizeRequest(Request{Targets: result.Input.Targets})
	if !reflect.DeepEqual(normalized, result.Input) {
		return fmt.Errorf("input does not match the normalized fixed retry policy")
	}
	if inputErr != nil {
		if result.Status != StatusStopped || result.StopReason != StopInvalidInput ||
			strings.TrimSpace(result.Detail) == "" || result.TargetsOmitted != 0 ||
			len(result.Targets) != 0 {
			return fmt.Errorf("invalid input requires stopped/invalid_input without attempts")
		}
		return nil
	}
	if result.Status == StatusStopped && result.StopReason == StopInvalidInput {
		return fmt.Errorf("valid input must not stop as invalid_input")
	}
	if err := validateTerminalShape(result); err != nil {
		return err
	}

	expectedTargets := boundedTargets(result.Input)
	if result.TargetsOmitted != omittedTargets(result.Input) {
		return fmt.Errorf("targets_omitted does not match the fixed target limit")
	}
	if len(result.Targets) != len(expectedTargets) {
		return fmt.Errorf("target results must match the bounded input schedule")
	}

	var source probe.Source
	hasSource := false
	for index, target := range result.Targets {
		if err := validateTarget(result, index, target, expectedTargets[index], &source, &hasSource); err != nil {
			return err
		}
	}
	if result.Status == StatusCompleted {
		for index, target := range result.Targets {
			if target.Status != TargetCompleted {
				return fmt.Errorf("completed batch target %d must be completed", index)
			}
		}
	}
	return nil
}

func validateTerminalShape(result Result) error {
	switch result.Status {
	case StatusCompleted:
		if result.StopReason != "" || result.Detail != "" {
			return fmt.Errorf("completed batch must not include a stop reason or detail")
		}
	case StatusStopped:
		switch result.StopReason {
		case StopBatchTimeout, StopInvalidProbeEvidence, StopSchedulerFailure:
		default:
			return fmt.Errorf("stopped batch has unsupported reason %q", result.StopReason)
		}
		if strings.TrimSpace(result.Detail) == "" {
			return fmt.Errorf("stopped batch requires detail")
		}
	case StatusCancelled:
		if result.StopReason != StopCancelled || strings.TrimSpace(result.Detail) == "" {
			return fmt.Errorf("cancelled batch requires cancelled reason and detail")
		}
	default:
		return fmt.Errorf("unsupported status %q", result.Status)
	}
	return nil
}

func validateTarget(
	result Result,
	index int,
	target TargetResult,
	expectedIP string,
	source *probe.Source,
	hasSource *bool,
) error {
	prefix := fmt.Sprintf("target %d", index)
	if target.DialIP != expectedIP || target.Family != targetFamily(expectedIP) {
		return fmt.Errorf("%s changes the normalized address or family", prefix)
	}
	if target.Attempts == nil {
		return fmt.Errorf("%s attempts must encode as an array", prefix)
	}
	switch target.Status {
	case TargetCompleted:
		if len(target.Attempts) == 0 {
			return fmt.Errorf("%s completed without an attempt", prefix)
		}
	case TargetInterrupted:
		if result.Status == StatusCompleted || len(target.Attempts) == 0 {
			return fmt.Errorf("%s interrupted status does not match its batch or attempts", prefix)
		}
	case TargetNotStarted:
		if result.Status == StatusCompleted || len(target.Attempts) != 0 {
			return fmt.Errorf("%s not_started status does not match its batch or attempts", prefix)
		}
	default:
		return fmt.Errorf("%s has unsupported status %q", prefix, target.Status)
	}
	if len(target.Attempts) > attemptLimit {
		return fmt.Errorf("%s exceeds the fixed attempt limit", prefix)
	}

	for attemptIndex, attempt := range target.Attempts {
		if attempt.Number != attemptIndex+1 {
			return fmt.Errorf("%s attempt %d has a non-sequential number", prefix, attemptIndex)
		}
		if attemptIndex == 0 {
			if attempt.RetryDelayMS != 0 {
				return fmt.Errorf("%s first attempt must not include retry delay", prefix)
			}
		} else {
			if attempt.RetryDelayMS < backoffMin.Milliseconds() ||
				attempt.RetryDelayMS > backoffMax.Milliseconds() {
				return fmt.Errorf("%s attempt %d retry delay is outside fixed bounds", prefix, attemptIndex)
			}
			if !shouldRetry(target.Attempts[attemptIndex-1].Observation) {
				return fmt.Errorf("%s attempt %d follows a non-retryable result", prefix, attemptIndex)
			}
		}
		if err := tlsobservation.Validate(attempt.Observation); err != nil {
			return fmt.Errorf("%s attempt %d: %w", prefix, attemptIndex, err)
		}
		if attempt.Observation.Platform != result.Platform ||
			attempt.Observation.Input != expectedTLSInput(expectedIP) {
			return fmt.Errorf("%s attempt %d changes the fixed platform or TLS request", prefix, attemptIndex)
		}
		if !*hasSource {
			*source = attempt.Observation.Source
			*hasSource = true
		} else if attempt.Observation.Source != *source {
			return fmt.Errorf("%s attempt %d changes the configured TLS adapter", prefix, attemptIndex)
		}
		if attempt.Observation.Outcome == probe.OutcomeCancelled {
			if target.Status != TargetInterrupted || attemptIndex != len(target.Attempts)-1 ||
				result.Status == StatusCompleted {
				return fmt.Errorf("%s cancelled attempt must terminate an interrupted batch target", prefix)
			}
		}
	}

	if target.Status == TargetCompleted {
		last := target.Attempts[len(target.Attempts)-1].Observation
		if last.Outcome == probe.OutcomeCancelled {
			return fmt.Errorf("%s completed with a cancelled attempt", prefix)
		}
		if len(target.Attempts) < attemptLimit && shouldRetry(last) {
			return fmt.Errorf("%s completed before exhausting a retryable result", prefix)
		}
	}
	return nil
}
