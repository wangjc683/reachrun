//go:build windows

package resolverinventory

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/wangjc683/reachrun/internal/probe"
	"golang.org/x/sys/windows"
)

const windowsAdapterBufferSize = 15 * 1024

var windowsSource = probe.Source{
	Backend:    "windows-ip-helper",
	Capability: probe.CapabilityNative,
}

func collectPlatform(ctx context.Context) (collected, error) {
	if err := ctx.Err(); err != nil {
		return collected{source: windowsSource}, err
	}

	adapters, buffer, err := getWindowsAdapters()
	if err != nil {
		return collected{source: windowsSource}, &collectError{
			code:   FailureUnavailable,
			source: windowsSource,
			err:    fmt.Errorf("GetAdaptersAddresses: %w", err),
		}
	}
	defer runtime.KeepAlive(buffer)

	groups := make([]Group, 0)
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}
		group, err := windowsAdapterGroup(adapter)
		if err != nil {
			return collected{source: windowsSource}, &collectError{
				code:   FailureInvalid,
				source: windowsSource,
				err:    err,
			}
		}
		if len(group.Servers) > 0 {
			groups = append(groups, group)
		}
	}
	if err := ctx.Err(); err != nil {
		return collected{source: windowsSource}, err
	}

	evidence, err := normalizeEvidence(Evidence{Groups: groups})
	if err != nil {
		return collected{source: windowsSource}, &collectError{
			code:   FailureInvalid,
			source: windowsSource,
			err:    err,
		}
	}
	return collected{evidence: evidence, source: windowsSource}, nil
}

func getWindowsAdapters() (*windows.IpAdapterAddresses, []byte, error) {
	size := uint32(windowsAdapterBufferSize)
	flags := uint32(
		windows.GAA_FLAG_SKIP_UNICAST |
			windows.GAA_FLAG_SKIP_ANYCAST |
			windows.GAA_FLAG_SKIP_MULTICAST,
	)

	for attempt := 0; attempt < 3; attempt++ {
		buffer := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, adapters, &size)
		if err == nil {
			return adapters, buffer, nil
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("adapter buffer size changed repeatedly")
}

func windowsAdapterGroup(adapter *windows.IpAdapterAddresses) (Group, error) {
	// Prefer the IPv6 index because a link-local IPv6 resolver needs its
	// interface scope when a later DNS observation constructs a dial target.
	index := adapter.Ipv6IfIndex
	if index == 0 {
		index = adapter.IfIndex
	}
	group := Group{
		Scope:          ScopeScoped,
		Servers:        make([]Server, 0),
		InterfaceIndex: index,
	}
	if adapter.FriendlyName != nil {
		group.Interface = windows.UTF16PtrToString(adapter.FriendlyName)
	}

	for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
		if server.Address.Sockaddr == nil {
			return Group{}, fmt.Errorf("adapter %q has an empty DNS server address", group.Interface)
		}
		ip := server.Address.IP()
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			return Group{}, fmt.Errorf("adapter %q has an invalid DNS server address", group.Interface)
		}
		zone := ""
		if address.Is6() && server.Address.Sockaddr.Addr.Family == windows.AF_INET6 {
			raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(server.Address.Sockaddr))
			if raw.Scope_id != 0 {
				zone = strconv.FormatUint(uint64(raw.Scope_id), 10)
			}
		}
		group.Servers = append(group.Servers, Server{
			Address: address.Unmap().String(),
			Port:    defaultDNSPort,
			Zone:    zone,
		})
	}

	if adapter.DnsSuffix != nil {
		if suffix := windows.UTF16PtrToString(adapter.DnsSuffix); suffix != "" {
			group.SearchDomains = append(group.SearchDomains, suffix)
		}
	}
	for suffix := adapter.FirstDnsSuffix; suffix != nil; suffix = suffix.Next {
		if value := windows.UTF16ToString(suffix.String[:]); value != "" {
			group.SearchDomains = append(group.SearchDomains, value)
		}
	}
	return normalizeGroup(group)
}
