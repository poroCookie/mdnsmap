package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type portRange struct {
	Start uint16
	End   uint16
}

type portRanges []portRange

func parsePortRanges(value string) (portRanges, error) {
	var ranges portRanges
	for _, part := range strings.Split(value, ",") {
		bounds := strings.SplitN(strings.TrimSpace(part), "-", 2)
		start, err := parsePort(bounds[0])
		if err != nil {
			return nil, err
		}
		end := start
		if len(bounds) == 2 {
			end, err = parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
		}
		if start > end {
			return nil, fmt.Errorf("端口范围起点大于终点：%s", part)
		}
		ranges = append(ranges, portRange{Start: start, End: end})
	}
	return ranges, nil
}

func parsePort(value string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("无效端口 %q", value)
	}
	return uint16(port), nil
}

func (ranges portRanges) Contains(port uint16) bool {
	for _, item := range ranges {
		if port >= item.Start && port <= item.End {
			return true
		}
	}
	return false
}

func containsAddress(prefixes []netip.Prefix, address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func chooseInterface(name string, cidrs []netip.Prefix) (*net.Interface, error) {
	if name != "" {
		return net.InterfaceByName(name)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("读取网卡失败: %w", err)
	}
	for index := range interfaces {
		candidate := &interfaces[index]
		if candidate.Flags&net.FlagUp == 0 || candidate.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, addressErr := candidate.Addrs()
		if addressErr != nil {
			continue
		}
		for _, rawAddress := range addresses {
			prefix, parseErr := netip.ParsePrefix(rawAddress.String())
			if parseErr == nil && prefixesOverlap(prefix.Masked(), cidrs) {
				return candidate, nil
			}
		}
	}
	return nil, fmt.Errorf("无法根据 CIDR 自动选择网卡，请传入 --interface")
}

func prefixesOverlap(local netip.Prefix, targets []netip.Prefix) bool {
	for _, target := range targets {
		if local.Addr().BitLen() != target.Addr().BitLen() {
			continue
		}
		if local.Contains(target.Addr()) || target.Contains(local.Addr()) {
			return true
		}
	}
	return false
}
