package sshobservation

import (
	"net/netip"

	"github.com/wangjc683/reachrun/internal/nettarget"
)

type configuredTarget struct {
	ip       netip.Addr
	port     uint16
	network  string
	endpoint string
}

func normalizeRequest(request Request) (Input, configuredTarget, error) {
	text, address, err := nettarget.NormalizePublicIP(request.DialIP)
	port := request.Port
	if port == 0 {
		port = DefaultPort
	}

	family := Family("")
	if address.IsValid() {
		family = FamilyIPv6
		if address.Is4() {
			family = FamilyIPv4
		}
	}
	input := Input{
		DialIP:               text,
		Family:               family,
		Port:                 port,
		ClientIdentification: ClientIdentification,
	}
	if err != nil {
		return input, configuredTarget{}, err
	}

	network := "tcp6"
	if address.Is4() {
		network = "tcp4"
	}
	return input, configuredTarget{
		ip:       address,
		port:     port,
		network:  network,
		endpoint: netip.AddrPortFrom(address, port).String(),
	}, nil
}
