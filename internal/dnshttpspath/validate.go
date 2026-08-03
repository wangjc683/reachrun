package dnshttpspath

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/probe"
)

// Validate checks the aggregate contract and every embedded DNS Observation.
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
	if result.DurationMS < 0 {
		return fmt.Errorf("duration_ms must not be negative")
	}
	if result.Platform.OS == "" || result.Platform.Arch == "" {
		return fmt.Errorf("platform must include OS and architecture")
	}
	if result.HTTPSObservations == nil || result.ServiceBindings == nil || result.AddressTargets == nil {
		return fmt.Errorf("evidence collections must encode as arrays")
	}

	normalized, inputErr := normalizeRequest(Request{
		Hostname:  result.Input.Hostname,
		Resolver:  result.Input.Resolver,
		Transport: result.Input.Transport,
	})
	if !reflect.DeepEqual(normalized, result.Input) {
		return fmt.Errorf("input does not match the normalized fixed policy")
	}
	if result.Status == StatusStopped && result.StopReason == StopInvalidInput {
		if inputErr == nil || len(result.HTTPSObservations) != 0 ||
			len(result.ServiceBindings) != 0 || len(result.AddressTargets) != 0 ||
			result.AliasesFollowed != 0 || result.ServiceTargetsOmitted != 0 {
			return fmt.Errorf("invalid_input must contain only a rejected input")
		}
		return validateTerminalShape(result)
	}
	if inputErr != nil {
		return fmt.Errorf("input is invalid: %w", inputErr)
	}
	if err := validateTerminalShape(result); err != nil {
		return err
	}
	if result.AliasesFollowed < 0 || result.AliasesFollowed > aliasLimit {
		return fmt.Errorf("aliases_followed must be between zero and %d", aliasLimit)
	}
	if result.ServiceTargetsOmitted < 0 {
		return fmt.Errorf("service_targets_omitted must not be negative")
	}
	if len(result.HTTPSObservations) == 0 {
		if result.AliasesFollowed != 0 || result.ServiceTargetsOmitted != 0 || result.Status == StatusCompleted {
			return fmt.Errorf("a completed path requires HTTPS evidence")
		}
		if result.Status == StatusStopped &&
			result.StopReason != StopPathTimeout &&
			result.StopReason != StopInvalidProbeEvidence {
			return fmt.Errorf("stop reason %q requires embedded HTTPS evidence", result.StopReason)
		}
		return nil
	}
	minimumAliases := len(result.HTTPSObservations) - 1
	if result.AliasesFollowed != minimumAliases && result.AliasesFollowed != len(result.HTTPSObservations) {
		return fmt.Errorf("aliases_followed does not match the HTTPS observation sequence")
	}
	if result.AliasesFollowed == len(result.HTTPSObservations) && result.Status == StatusCompleted {
		return fmt.Errorf("completed path cannot end before an followed alias is observed")
	}
	if result.AliasesFollowed == len(result.HTTPSObservations) &&
		result.Status != StatusCancelled &&
		result.StopReason != StopPathTimeout &&
		result.StopReason != StopInvalidProbeEvidence {
		return fmt.Errorf("a followed but unobserved alias requires timeout, cancellation, or invalid evidence")
	}

	queriedNames := make(map[string]struct{}, len(result.HTTPSObservations)*2)
	resolverEndpoint := result.HTTPSObservations[0].Input.Resolver.Endpoint
	source := result.HTTPSObservations[0].Source
	for index, observation := range result.HTTPSObservations {
		if err := validateEmbeddedObservation(
			observation,
			result.Platform,
			result.Input,
			observation.Input.Hostname,
			dnsobservation.QueryTypeHTTPS,
		); err != nil {
			return fmt.Errorf("HTTPS observation %d: %w", index, err)
		}
		if observation.Input.Resolver.Endpoint != resolverEndpoint || observation.Source != source {
			return fmt.Errorf("HTTPS observation %d does not use the same configured resolver adapter", index)
		}
		if index == 0 && observation.Input.Hostname != result.Input.Hostname {
			return fmt.Errorf("first HTTPS observation does not query the input hostname")
		}
		queriedNames[observation.Input.Hostname] = struct{}{}
		if observation.Outcome == probe.OutcomeSucceeded {
			queriedNames[observation.Evidence.EffectiveName] = struct{}{}
		}
		if index == len(result.HTTPSObservations)-1 {
			continue
		}
		if observation.Outcome != probe.OutcomeSucceeded ||
			observation.Evidence.AnswerKind == dnsobservation.AnswerKindIncomplete {
			return fmt.Errorf("nonterminal HTTPS observation %d is not complete", index)
		}
		aliases, _ := relevantBindings(*observation.Evidence)
		if len(aliases) == 0 || aliases[0].record.Service.Target != result.HTTPSObservations[index+1].Input.Hostname {
			return fmt.Errorf("HTTPS observation %d does not restart at its first AliasMode target", index)
		}
	}

	last := result.HTTPSObservations[len(result.HTTPSObservations)-1]
	if last.Outcome != probe.OutcomeSucceeded {
		if result.Status == StatusCompleted {
			return fmt.Errorf("completed path cannot end with a failed HTTPS observation")
		}
		if len(result.ServiceBindings) != 0 || len(result.AddressTargets) != 0 ||
			result.ServiceTargetsOmitted != 0 {
			return fmt.Errorf("failed HTTPS observation must be terminal before final targets")
		}
		return validateStopEvidence(result, queriedNames)
	}
	aliases, services := relevantBindings(*last.Evidence)
	if last.Evidence.AnswerKind == dnsobservation.AnswerKindIncomplete {
		if result.Status == StatusCompleted {
			return fmt.Errorf("completed path cannot end with incomplete HTTPS evidence")
		}
		if len(result.ServiceBindings) != 0 || len(result.AddressTargets) != 0 ||
			result.ServiceTargetsOmitted != 0 {
			return fmt.Errorf("incomplete HTTPS evidence must not produce final targets")
		}
		return validateStopEvidence(result, queriedNames)
	}

	expectedDecisions := make([]BindingDecision, 0)
	expectedTargets := make([]AddressTarget, 0)
	expectedOmitted := 0
	if len(aliases) == 0 && len(services) > 0 {
		expectedDecisions = evaluateBindings(services)
		expectedTargets = serviceAddressTargets(expectedDecisions)
		if len(expectedTargets) > result.Input.ServiceTargetLimit {
			expectedOmitted = len(expectedTargets) - result.Input.ServiceTargetLimit
			expectedTargets = expectedTargets[:result.Input.ServiceTargetLimit]
		}
	} else if len(aliases) == 0 && last.Evidence.EffectiveName != "." {
		source := TargetOriginFallback
		if result.AliasesFollowed > 0 {
			source = TargetAliasFallback
		}
		expectedTargets = []AddressTarget{{
			Hostname:     last.Evidence.EffectiveName,
			Source:       source,
			Observations: make([]dnsobservation.Result, 0),
		}}
	}
	if !reflect.DeepEqual(result.ServiceBindings, expectedDecisions) {
		return fmt.Errorf("service_bindings do not match the final HTTPS records")
	}
	if result.ServiceTargetsOmitted != expectedOmitted {
		return fmt.Errorf("service_targets_omitted does not match final HTTPS evidence")
	}
	if err := validateAddressTargets(result, expectedTargets, resolverEndpoint, source); err != nil {
		return err
	}
	if result.Status == StatusCompleted {
		return validateCompletion(result, aliases, services, expectedDecisions)
	}
	return validateStopEvidence(result, queriedNames)
}

func validateTerminalShape(result Result) error {
	switch result.Status {
	case StatusCompleted:
		if !result.Completion.valid() || result.StopReason != "" || result.Detail != "" {
			return fmt.Errorf("completed path requires one completion and no stop reason or detail")
		}
	case StatusStopped:
		if result.Completion != "" || !result.StopReason.valid() || result.StopReason == StopCancelled ||
			strings.TrimSpace(result.Detail) == "" {
			return fmt.Errorf("stopped path requires a non-cancel stop reason and detail")
		}
	case StatusCancelled:
		if result.Completion != "" || result.StopReason != StopCancelled {
			return fmt.Errorf("cancelled path requires cancelled stop reason")
		}
	default:
		return fmt.Errorf("unsupported status %q", result.Status)
	}
	return nil
}

func validateEmbeddedObservation(
	observation dnsobservation.Result,
	platform probe.Platform,
	input Input,
	hostname string,
	queryType dnsobservation.QueryType,
) error {
	if err := dnsobservation.Validate(observation); err != nil {
		return err
	}
	if observation.Platform != platform ||
		observation.Input.Hostname != hostname ||
		observation.Input.QueryType != queryType ||
		observation.Input.Resolver.ID != input.Resolver ||
		observation.Input.Transport != input.Transport {
		return fmt.Errorf("observation does not match the path platform, resolver, transport, hostname, or query type")
	}
	return nil
}

func validateAddressTargets(
	result Result,
	expected []AddressTarget,
	resolverEndpoint string,
	source probe.Source,
) error {
	if len(result.AddressTargets) != len(expected) {
		return fmt.Errorf("address_targets count does not match final HTTPS evidence")
	}
	for targetIndex, target := range result.AddressTargets {
		want := expected[targetIndex]
		if target.Hostname != want.Hostname || target.Source != want.Source || target.Priority != want.Priority {
			return fmt.Errorf("address target %d metadata does not match final HTTPS evidence", targetIndex)
		}
		if target.Observations == nil {
			return fmt.Errorf("address target %d observations must encode as an array", targetIndex)
		}
		if len(target.Observations) > len(result.Input.AddressQueryTypes) {
			return fmt.Errorf("address target %d has too many observations", targetIndex)
		}
		for observationIndex, observation := range target.Observations {
			queryType := result.Input.AddressQueryTypes[observationIndex]
			if err := validateEmbeddedObservation(
				observation,
				result.Platform,
				result.Input,
				target.Hostname,
				queryType,
			); err != nil {
				return fmt.Errorf("address target %d observation %d: %w", targetIndex, observationIndex, err)
			}
			if observation.Input.Resolver.Endpoint != resolverEndpoint || observation.Source != source {
				return fmt.Errorf("address target %d observation %d changes the configured resolver adapter", targetIndex, observationIndex)
			}
		}
		if result.Status == StatusCompleted {
			if len(target.Observations) != len(result.Input.AddressQueryTypes) {
				return fmt.Errorf("completed address target %d lacks A or AAAA evidence", targetIndex)
			}
			for _, observation := range target.Observations {
				if observation.Outcome != probe.OutcomeSucceeded ||
					observation.Evidence.AnswerKind == dnsobservation.AnswerKindIncomplete {
					return fmt.Errorf("completed address target %d includes incomplete probe evidence", targetIndex)
				}
			}
		}
	}
	return nil
}

func validateCompletion(
	result Result,
	aliases []bindingReference,
	services []bindingReference,
	decisions []BindingDecision,
) error {
	switch result.Completion {
	case CompletionServiceMode:
		if len(aliases) != 0 || len(services) == 0 || !hasUsableBinding(decisions) ||
			len(result.AddressTargets) == 0 {
			return fmt.Errorf("service_mode completion does not match final HTTPS evidence")
		}
	case CompletionUnsupportedServiceMode:
		if len(aliases) != 0 || len(services) == 0 || hasUsableBinding(decisions) ||
			len(result.AddressTargets) != 0 {
			return fmt.Errorf("unsupported_service_mode does not match final HTTPS evidence")
		}
	case CompletionAliasFallback:
		if result.AliasesFollowed == 0 || len(aliases) != 0 || len(services) != 0 ||
			len(result.AddressTargets) != 1 || result.AddressTargets[0].Source != TargetAliasFallback {
			return fmt.Errorf("alias_fallback does not match final HTTPS evidence")
		}
	case CompletionOriginFallback:
		if result.AliasesFollowed != 0 || len(aliases) != 0 || len(services) != 0 ||
			len(result.AddressTargets) != 1 || result.AddressTargets[0].Source != TargetOriginFallback {
			return fmt.Errorf("origin_fallback does not match final HTTPS evidence")
		}
	case CompletionServiceUnavailable:
		unavailable := result.HTTPSObservations[len(result.HTTPSObservations)-1].Evidence.EffectiveName == "." ||
			(len(aliases) > 0 && aliases[0].record.Service.Target == ".")
		if !unavailable || len(result.AddressTargets) != 0 {
			return fmt.Errorf("service_unavailable does not match final HTTPS evidence")
		}
	}
	return nil
}

func validateStopEvidence(result Result, queriedNames map[string]struct{}) error {
	hasFailure := false
	hasIncomplete := false
	for _, observation := range result.HTTPSObservations {
		hasFailure = hasFailure || observation.Outcome == probe.OutcomeFailed
		hasIncomplete = hasIncomplete ||
			(observation.Outcome == probe.OutcomeSucceeded &&
				observation.Evidence.AnswerKind == dnsobservation.AnswerKindIncomplete)
	}
	for _, target := range result.AddressTargets {
		for _, observation := range target.Observations {
			hasFailure = hasFailure || observation.Outcome == probe.OutcomeFailed
			hasIncomplete = hasIncomplete ||
				(observation.Outcome == probe.OutcomeSucceeded &&
					observation.Evidence.AnswerKind == dnsobservation.AnswerKindIncomplete)
		}
	}

	switch result.StopReason {
	case StopDNSObservationFailed:
		if !hasFailure {
			return fmt.Errorf("dns_observation_failed requires failed embedded evidence")
		}
	case StopDNSObservationIncomplete:
		if !hasIncomplete {
			return fmt.Errorf("dns_observation_incomplete requires incomplete embedded evidence")
		}
	case StopAliasLoop, StopAliasLimit:
		last := result.HTTPSObservations[len(result.HTTPSObservations)-1]
		if last.Outcome != probe.OutcomeSucceeded {
			return fmt.Errorf("alias stop requires a successful final HTTPS observation")
		}
		aliases, _ := relevantBindings(*last.Evidence)
		if len(aliases) == 0 || aliases[0].record.Service.Target == "." {
			return fmt.Errorf("alias stop requires a followable AliasMode target")
		}
		target := aliases[0].record.Service.Target
		_, repeated := queriedNames[target]
		if result.StopReason == StopAliasLoop && !repeated {
			return fmt.Errorf("alias_loop target does not repeat the observed chain")
		}
		if result.StopReason == StopAliasLimit && (repeated || result.AliasesFollowed != aliasLimit) {
			return fmt.Errorf("alias_limit does not match the bounded chain")
		}
	}
	return nil
}

func hasUsableBinding(decisions []BindingDecision) bool {
	for _, decision := range decisions {
		if decision.Usable {
			return true
		}
	}
	return false
}

func (completion CompletionKind) valid() bool {
	switch completion {
	case CompletionServiceMode,
		CompletionAliasFallback,
		CompletionOriginFallback,
		CompletionServiceUnavailable,
		CompletionUnsupportedServiceMode:
		return true
	default:
		return false
	}
}

func (reason StopReason) valid() bool {
	switch reason {
	case StopInvalidInput,
		StopDNSObservationFailed,
		StopDNSObservationIncomplete,
		StopAliasLoop,
		StopAliasLimit,
		StopPathTimeout,
		StopCancelled,
		StopInvalidProbeEvidence:
		return true
	default:
		return false
	}
}
