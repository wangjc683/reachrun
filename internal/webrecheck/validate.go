package webrecheck

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

// Validate checks the aggregate contract and every embedded Web Observation.
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
	if result.Attempts == nil {
		return fmt.Errorf("attempts must encode as an array")
	}

	normalized, inputErr := normalizeRequest(Request{
		Hostname:            result.Input.Hostname,
		LocalCandidates:     result.Input.LocalCandidates,
		ReferenceCandidates: result.Input.ReferenceCandidates,
	})
	if !reflect.DeepEqual(normalized, result.Input) {
		return fmt.Errorf("input does not match the normalized fixed policy")
	}
	if inputErr != nil {
		if result.Status != StatusStopped || result.StopReason != StopInvalidInput ||
			strings.TrimSpace(result.Detail) == "" || len(result.Attempts) != 0 ||
			result.LocalCandidatesOmitted != 0 || result.ReferenceCandidatesOmitted != 0 {
			return fmt.Errorf("invalid input requires stopped/invalid_input without evidence")
		}
		return nil
	}
	if result.Status == StatusStopped && result.StopReason == StopInvalidInput {
		return fmt.Errorf("valid input must not stop as invalid_input")
	}
	if err := validateTerminalShape(result); err != nil {
		return err
	}

	wantLocalOmitted := omittedCandidates(result.Input.LocalCandidates)
	wantReferenceOmitted := omittedCandidates(result.Input.ReferenceCandidates)
	if result.LocalCandidatesOmitted != wantLocalOmitted ||
		result.ReferenceCandidatesOmitted != wantReferenceOmitted {
		return fmt.Errorf("candidate omitted counts do not match the fixed limit")
	}

	expected := schedule(result.Input)
	if len(result.Attempts) > len(expected) {
		return fmt.Errorf("attempts exceed the bounded candidate schedule")
	}
	if result.Status == StatusCompleted && len(result.Attempts) != len(expected) {
		return fmt.Errorf("completed recheck requires every bounded candidate attempt")
	}
	if result.Status == StatusStopped && result.StopReason == StopInvalidProbeEvidence &&
		len(result.Attempts) == len(expected) {
		return fmt.Errorf("invalid_probe_evidence must stop before the full schedule")
	}

	var source probe.Source
	for index, attempt := range result.Attempts {
		want := expected[index]
		if attempt.CandidateSource != want.source {
			return fmt.Errorf("attempt %d does not follow the alternating source schedule", index)
		}
		if err := webobservation.Validate(attempt.Observation); err != nil {
			return fmt.Errorf("attempt %d: %w", index, err)
		}
		expectedInput := webobservation.Input{
			Scheme:   result.Input.Scheme,
			Hostname: result.Input.Hostname,
			DialIP:   want.ip,
			Family:   result.Input.Family,
			Port:     result.Input.Port,
			Method:   result.Input.Method,
			Path:     result.Input.Path,
		}
		if attempt.Observation.Platform != result.Platform ||
			attempt.Observation.Input != expectedInput {
			return fmt.Errorf("attempt %d changes the fixed platform or first-hop request", index)
		}
		if index == 0 {
			source = attempt.Observation.Source
		} else if attempt.Observation.Source != source {
			return fmt.Errorf("attempt %d changes the configured Web adapter", index)
		}
		if attempt.Observation.Outcome == probe.OutcomeCancelled {
			if result.Status != StatusCancelled || index != len(result.Attempts)-1 {
				return fmt.Errorf("cancelled Web attempt must terminate a cancelled recheck")
			}
		}
	}

	if result.Status == StatusCompleted {
		for index, attempt := range result.Attempts {
			if attempt.Observation.Outcome == probe.OutcomeCancelled {
				return fmt.Errorf("completed recheck includes cancelled attempt %d", index)
			}
		}
	}
	return nil
}

func validateTerminalShape(result Result) error {
	switch result.Status {
	case StatusCompleted:
		if result.StopReason != "" || result.Detail != "" {
			return fmt.Errorf("completed recheck must not include a stop reason or detail")
		}
	case StatusStopped:
		if (result.StopReason != StopRecheckTimeout &&
			result.StopReason != StopInvalidProbeEvidence) ||
			strings.TrimSpace(result.Detail) == "" {
			return fmt.Errorf("stopped recheck requires a supported reason and detail")
		}
	case StatusCancelled:
		if result.StopReason != StopCancelled {
			return fmt.Errorf("cancelled recheck requires cancelled stop reason")
		}
	default:
		return fmt.Errorf("unsupported status %q", result.Status)
	}
	return nil
}
