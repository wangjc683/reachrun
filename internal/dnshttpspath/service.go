package dnshttpspath

import (
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
)

const (
	serviceParamMandatory     uint16 = 0
	serviceParamALPN          uint16 = 1
	serviceParamNoDefaultALPN uint16 = 2
	serviceParamPort          uint16 = 3
	serviceParamIPv4Hint      uint16 = 4
	serviceParamIPv6Hint      uint16 = 6

	httpsDefaultPort uint16 = 443
)

type bindingReference struct {
	recordIndex int
	record      dnsobservation.Record
}

func relevantBindings(evidence dnsobservation.Evidence) (aliases, services []bindingReference) {
	for index, record := range evidence.Records {
		if record.Type != dnsobservation.QueryTypeHTTPS ||
			record.Name != evidence.EffectiveName ||
			record.Service == nil {
			continue
		}
		reference := bindingReference{recordIndex: index, record: record}
		if record.Service.Mode == dnsobservation.ServiceBindingAlias {
			aliases = append(aliases, reference)
		} else {
			services = append(services, reference)
		}
	}
	return aliases, services
}

func evaluateBindings(services []bindingReference) []BindingDecision {
	decisions := make([]BindingDecision, 0, len(services))
	for _, service := range services {
		decisions = append(decisions, evaluateBinding(service))
	}
	return decisions
}

func evaluateBinding(reference bindingReference) BindingDecision {
	binding := reference.record.Service
	addressHostname := binding.Target
	if addressHostname == "." {
		addressHostname = reference.record.Name
	}
	decision := BindingDecision{
		RecordIndex:     reference.recordIndex,
		Priority:        binding.Priority,
		AddressHostname: addressHostname,
		Usable:          true,
		Reason:          BindingUsable,
	}

	values := make(map[uint16][]byte, len(binding.Params))
	malformed := make([]uint16, 0)
	for _, param := range binding.Params {
		value, err := hex.DecodeString(param.ValueHex)
		if err != nil {
			malformed = append(malformed, param.Key)
			continue
		}
		values[param.Key] = value
		switch param.Key {
		case serviceParamMandatory:
			if _, ok := mandatoryKeys(value); !ok {
				malformed = append(malformed, param.Key)
			}
		case serviceParamALPN:
			if _, ok := alpnIDs(value); !ok {
				malformed = append(malformed, param.Key)
			}
		case serviceParamNoDefaultALPN:
			if len(value) != 0 {
				malformed = append(malformed, param.Key)
			}
		case serviceParamPort:
			if len(value) != 2 {
				malformed = append(malformed, param.Key)
			}
		case serviceParamIPv4Hint:
			if len(value) == 0 || len(value)%4 != 0 {
				malformed = append(malformed, param.Key)
			}
		case serviceParamIPv6Hint:
			if len(value) == 0 || len(value)%16 != 0 {
				malformed = append(malformed, param.Key)
			}
		}
	}

	if _, noDefault := values[serviceParamNoDefaultALPN]; noDefault {
		if _, hasALPN := values[serviceParamALPN]; !hasALPN {
			malformed = append(malformed, serviceParamNoDefaultALPN)
		}
	}
	if mandatory, ok := values[serviceParamMandatory]; ok {
		keys, valid := mandatoryKeys(mandatory)
		if valid {
			for _, key := range keys {
				if key == serviceParamMandatory {
					malformed = append(malformed, key)
					continue
				}
				if _, present := values[key]; !present {
					malformed = append(malformed, key)
				}
			}
		}
	}
	if len(malformed) > 0 {
		decision.Usable = false
		decision.Reason = BindingMalformedParameters
		decision.UnsupportedParameterKeys = normalizedKeys(malformed)
		return decision
	}

	unsupported := make([]uint16, 0)
	if mandatory, ok := values[serviceParamMandatory]; ok {
		keys, _ := mandatoryKeys(mandatory)
		for _, key := range keys {
			if !supportedMandatoryKey(key) {
				unsupported = append(unsupported, key)
			}
		}
	}
	if port, ok := values[serviceParamPort]; ok && binary.BigEndian.Uint16(port) != httpsDefaultPort {
		unsupported = append(unsupported, serviceParamPort)
	}
	if _, noDefault := values[serviceParamNoDefaultALPN]; noDefault {
		ids, _ := alpnIDs(values[serviceParamALPN])
		if !containsALPN(ids, "http/1.1") {
			unsupported = append(unsupported, serviceParamALPN, serviceParamNoDefaultALPN)
		}
	}
	if len(unsupported) > 0 {
		decision.Usable = false
		decision.Reason = BindingUnsupportedParameters
		decision.UnsupportedParameterKeys = normalizedKeys(unsupported)
	}
	return decision
}

func mandatoryKeys(value []byte) ([]uint16, bool) {
	if len(value) == 0 || len(value)%2 != 0 {
		return nil, false
	}
	keys := make([]uint16, 0, len(value)/2)
	var previous uint16
	for offset := 0; offset < len(value); offset += 2 {
		key := binary.BigEndian.Uint16(value[offset : offset+2])
		if len(keys) > 0 && key <= previous {
			return nil, false
		}
		keys = append(keys, key)
		previous = key
	}
	return keys, true
}

func alpnIDs(value []byte) ([][]byte, bool) {
	if len(value) == 0 {
		return nil, false
	}
	ids := make([][]byte, 0)
	for offset := 0; offset < len(value); {
		length := int(value[offset])
		offset++
		if length == 0 || offset+length > len(value) {
			return nil, false
		}
		ids = append(ids, value[offset:offset+length])
		offset += length
	}
	return ids, true
}

func containsALPN(ids [][]byte, wanted string) bool {
	for _, id := range ids {
		if string(id) == wanted {
			return true
		}
	}
	return false
}

func supportedMandatoryKey(key uint16) bool {
	switch key {
	case serviceParamALPN,
		serviceParamNoDefaultALPN,
		serviceParamPort:
		return true
	default:
		return false
	}
}

func normalizedKeys(keys []uint16) []uint16 {
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	result := keys[:0]
	for _, key := range keys {
		if len(result) == 0 || result[len(result)-1] != key {
			result = append(result, key)
		}
	}
	return result
}

func serviceAddressTargets(decisions []BindingDecision) []AddressTarget {
	usable := make([]BindingDecision, 0, len(decisions))
	for _, decision := range decisions {
		if decision.Usable {
			usable = append(usable, decision)
		}
	}
	sort.SliceStable(usable, func(i, j int) bool {
		return usable[i].Priority < usable[j].Priority
	})

	targets := make([]AddressTarget, 0, len(usable))
	seen := make(map[string]struct{}, len(usable))
	for _, decision := range usable {
		if _, duplicate := seen[decision.AddressHostname]; duplicate {
			continue
		}
		seen[decision.AddressHostname] = struct{}{}
		targets = append(targets, AddressTarget{
			Hostname:     decision.AddressHostname,
			Source:       TargetServiceMode,
			Priority:     decision.Priority,
			Observations: make([]dnsobservation.Result, 0, 2),
		})
	}
	return targets
}
