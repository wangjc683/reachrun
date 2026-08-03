package dnshttpspath

import (
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
)

func TestEvaluateBindingCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		params          []dnsobservation.ServiceParameter
		usable          bool
		reason          BindingReason
		unsupportedKeys []uint16
	}{
		{name: "default HTTPS", usable: true, reason: BindingUsable},
		{
			name: "explicit default port",
			params: []dnsobservation.ServiceParameter{{
				Key: serviceParamPort, Name: "port", ValueHex: "01bb",
			}},
			usable: true, reason: BindingUsable,
		},
		{
			name: "nondefault port",
			params: []dnsobservation.ServiceParameter{{
				Key: serviceParamPort, Name: "port", ValueHex: "20fb",
			}},
			usable: false, reason: BindingUnsupportedParameters,
			unsupportedKeys: []uint16{serviceParamPort},
		},
		{
			name: "no default ALPN with HTTP one",
			params: []dnsobservation.ServiceParameter{
				{Key: serviceParamALPN, Name: "alpn", ValueHex: "08687474702f312e31"},
				{Key: serviceParamNoDefaultALPN, Name: "no-default-alpn", ValueHex: ""},
			},
			usable: true, reason: BindingUsable,
		},
		{
			name: "no default ALPN with h2 only",
			params: []dnsobservation.ServiceParameter{
				{Key: serviceParamALPN, Name: "alpn", ValueHex: "026832"},
				{Key: serviceParamNoDefaultALPN, Name: "no-default-alpn", ValueHex: ""},
			},
			usable: false, reason: BindingUnsupportedParameters,
			unsupportedKeys: []uint16{serviceParamALPN, serviceParamNoDefaultALPN},
		},
		{
			name: "unknown mandatory key",
			params: []dnsobservation.ServiceParameter{
				{Key: serviceParamMandatory, Name: "mandatory", ValueHex: "fde8"},
				{Key: 65000, Name: "key65000", ValueHex: "01"},
			},
			usable: false, reason: BindingUnsupportedParameters,
			unsupportedKeys: []uint16{65000},
		},
		{
			name: "mandatory hint is not treated as address truth",
			params: []dnsobservation.ServiceParameter{
				{Key: serviceParamMandatory, Name: "mandatory", ValueHex: "0004"},
				{Key: serviceParamIPv4Hint, Name: "ipv4hint", ValueHex: "c0000201"},
			},
			usable: false, reason: BindingUnsupportedParameters,
			unsupportedKeys: []uint16{serviceParamIPv4Hint},
		},
		{
			name: "mandatory key missing parameter",
			params: []dnsobservation.ServiceParameter{{
				Key: serviceParamMandatory, Name: "mandatory", ValueHex: "0001",
			}},
			usable: false, reason: BindingMalformedParameters,
			unsupportedKeys: []uint16{serviceParamALPN},
		},
		{
			name: "malformed ALPN",
			params: []dnsobservation.ServiceParameter{{
				Key: serviceParamALPN, Name: "alpn", ValueHex: "036832",
			}},
			usable: false, reason: BindingMalformedParameters,
			unsupportedKeys: []uint16{serviceParamALPN},
		},
		{
			name: "empty IPv4 hint",
			params: []dnsobservation.ServiceParameter{{
				Key: serviceParamIPv4Hint, Name: "ipv4hint", ValueHex: "",
			}},
			usable: false, reason: BindingMalformedParameters,
			unsupportedKeys: []uint16{serviceParamIPv4Hint},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := serviceRecord("www.example.com", 1, "svc.example.net", test.params)
			decision := evaluateBinding(bindingReference{recordIndex: 4, record: record})
			if decision.RecordIndex != 4 || decision.AddressHostname != "svc.example.net" ||
				decision.Usable != test.usable || decision.Reason != test.reason ||
				!reflect.DeepEqual(decision.UnsupportedParameterKeys, test.unsupportedKeys) {
				t.Fatalf("decision = %#v, want usable=%t reason=%q keys=%v", decision, test.usable, test.reason, test.unsupportedKeys)
			}
		})
	}
}

func TestEvaluateBindingUsesOwnerForDotTarget(t *testing.T) {
	t.Parallel()

	record := serviceRecord("www.example.com", 1, ".", nil)
	decision := evaluateBinding(bindingReference{recordIndex: 0, record: record})
	if !decision.Usable || decision.AddressHostname != "www.example.com" {
		t.Fatalf("dot-target decision = %#v, want owner hostname", decision)
	}
}
