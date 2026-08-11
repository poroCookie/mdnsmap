package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

const serviceEnumeration = "_services._dns-sd._udp.local."

var commonServices = []string{
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_smb._tcp.local.",
	"_qdiscover._tcp.local.",
	"_device-info._tcp.local.",
	"_afpovertcp._tcp.local.",
}

type scanConfig struct {
	CIDRs         []netip.Prefix
	Ports         portRanges
	InterfaceName string
	Timeout       time.Duration
	StrictTTL     bool
}

type addressRecord struct {
	Address netip.Addr
	TTL     uint32
}

type instanceState struct {
	ServiceType string
	Instance    string
	Host        string
	Port        uint16
	Transport   string
	TXT         []string
	TTLValues   []uint32
	Source      netip.Addr
}

type inventory struct {
	instances    map[string]*instanceState
	addresses    map[string][]addressRecord
	serviceTypes map[string]struct{}
}

type finding struct {
	IP           string            `json:"ip"`
	IPv4         []string          `json:"ipv4,omitempty"`
	IPv6         []string          `json:"ipv6,omitempty"`
	Port         *uint16           `json:"port"`
	Transport    string            `json:"transport"`
	Host         string            `json:"host,omitempty"`
	Service      string            `json:"service"`
	Instance     string            `json:"instance"`
	State        string            `json:"state"`
	MetadataOnly bool              `json:"metadata_only"`
	TTL          uint32            `json:"ttl"`
	TXTRaw       []string          `json:"txt_raw,omitempty"`
	Fingerprint  map[string]string `json:"fingerprint,omitempty"`
	Banner       string            `json:"banner"`
}

func newInventory() *inventory {
	return &inventory{
		instances:    make(map[string]*instanceState),
		addresses:    make(map[string][]addressRecord),
		serviceTypes: make(map[string]struct{}),
	}
}

func scan(config scanConfig) ([]finding, []string, error) {
	networkInterface, err := chooseInterface(config.InterfaceName, config.CIDRs)
	if err != nil {
		return nil, nil, err
	}
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	connection, err := net.ListenMulticastUDP("udp4", networkInterface, group)
	if err != nil {
		return nil, nil, fmt.Errorf("在网卡 %s 监听 mDNS 失败: %w", networkInterface.Name, err)
	}
	defer connection.Close()
	_ = connection.SetReadBuffer(1 << 20)
	packetConnection := ipv4.NewPacketConn(connection)
	if err = packetConnection.SetControlMessage(ipv4.FlagTTL|ipv4.FlagInterface, true); err != nil {
		return nil, nil, fmt.Errorf("启用 mDNS 控制消息失败: %w", err)
	}
	if err = packetConnection.SetMulticastInterface(networkInterface); err != nil {
		return nil, nil, fmt.Errorf("设置组播网卡失败: %w", err)
	}
	if err = packetConnection.SetMulticastTTL(255); err != nil {
		return nil, nil, fmt.Errorf("设置组播 TTL 失败: %w", err)
	}

	collector := newInventory()
	queried := make(map[string]struct{})
	sendQuery := func(name string, recordTypes ...uint16) {
		for _, recordType := range recordTypes {
			queryKey := fmt.Sprintf("%s/%d", canonicalName(name), recordType)
			if _, exists := queried[queryKey]; exists {
				continue
			}
			queried[queryKey] = struct{}{}
			if queryErr := writeQuery(packetConnection, group, name, recordType); queryErr != nil {
				fmt.Fprintf(os.Stderr, "警告：发送 mDNS 查询 %s 失败：%v\n", name, queryErr)
			}
		}
	}
	sendInitialQueries(sendQuery)

	deadline := time.Now().Add(config.Timeout)
	buffer := make([]byte, 65535)
	for time.Now().Before(deadline) {
		_ = connection.SetReadDeadline(deadline)
		length, control, source, readErr := packetConnection.ReadFrom(buffer)
		if readErr != nil {
			var networkError net.Error
			if errors.As(readErr, &networkError) && networkError.Timeout() {
				break
			}
			return nil, nil, fmt.Errorf("读取 mDNS 响应失败: %w", readErr)
		}
		if config.StrictTTL && (control == nil || control.TTL != 255) {
			continue
		}
		message := new(dns.Msg)
		if unpackErr := message.Unpack(buffer[:length]); unpackErr != nil {
			fmt.Fprintf(os.Stderr, "警告：忽略无法解析的 mDNS 响应：%v\n", unpackErr)
			continue
		}
		collector.ingest(message, sourceAddress(source), sendQuery)
	}
	return collector.buildFindings(config.CIDRs, config.Ports, networkInterface.Name), collector.sortedServiceTypes(), nil
}

func sendInitialQueries(send func(string, ...uint16)) {
	send(serviceEnumeration, dns.TypePTR)
	for _, service := range commonServices {
		send(service, dns.TypePTR)
	}
}

func writeQuery(connection *ipv4.PacketConn, group *net.UDPAddr, name string, recordType uint16) error {
	message := new(dns.Msg)
	message.Id = 0
	message.RecursionDesired = false
	message.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: recordType, Qclass: dns.ClassINET}}
	payload, err := message.Pack()
	if err != nil {
		return err
	}
	_, err = connection.WriteTo(payload, nil, group)
	return err
}

func (collector *inventory) ingest(message *dns.Msg, source netip.Addr, send func(string, ...uint16)) {
	records := append(append(append([]dns.RR{}, message.Answer...), message.Ns...), message.Extra...)
	for _, record := range records {
		switch value := record.(type) {
		case *dns.PTR:
			collector.ingestPTR(value, source, send)
		case *dns.SRV:
			state := collector.instance(value.Hdr.Name)
			state.Host = canonicalName(value.Target)
			state.Port = value.Port
			state.Source = source
			state.TTLValues = append(state.TTLValues, value.Hdr.Ttl)
			send(value.Target, dns.TypeA, dns.TypeAAAA)
		case *dns.TXT:
			state := collector.instance(value.Hdr.Name)
			state.TXT = appendUnique(state.TXT, value.Txt...)
			state.Source = source
			state.TTLValues = append(state.TTLValues, value.Hdr.Ttl)
		case *dns.A:
			collector.addAddress(value.Hdr.Name, value.A, value.Hdr.Ttl)
		case *dns.AAAA:
			collector.addAddress(value.Hdr.Name, value.AAAA, value.Hdr.Ttl)
		}
	}
}

func (collector *inventory) ingestPTR(record *dns.PTR, source netip.Addr, send func(string, ...uint16)) {
	owner := canonicalName(record.Hdr.Name)
	target := canonicalName(record.Ptr)
	if owner == canonicalName(serviceEnumeration) {
		collector.serviceTypes[target] = struct{}{}
		send(target, dns.TypePTR)
		return
	}
	service, transport, valid := parseServiceType(owner)
	if !valid {
		return
	}
	collector.serviceTypes[owner] = struct{}{}
	state := collector.instance(target)
	state.ServiceType = owner
	state.Transport = transport
	state.Source = source
	state.TTLValues = append(state.TTLValues, record.Hdr.Ttl)
	state.Instance = instanceDisplayName(record.Ptr, record.Hdr.Name)
	_ = service
	send(target, dns.TypeSRV, dns.TypeTXT)
}

func (collector *inventory) instance(name string) *instanceState {
	key := canonicalName(name)
	state, exists := collector.instances[key]
	if !exists {
		state = &instanceState{}
		collector.instances[key] = state
	}
	return state
}

func (collector *inventory) addAddress(host string, raw net.IP, ttl uint32) {
	address, ok := netip.AddrFromSlice(raw)
	if !ok {
		return
	}
	key := canonicalName(host)
	record := addressRecord{Address: address.Unmap(), TTL: ttl}
	for _, existing := range collector.addresses[key] {
		if existing.Address == record.Address {
			return
		}
	}
	collector.addresses[key] = append(collector.addresses[key], record)
}

func (collector *inventory) buildFindings(cidrs []netip.Prefix, ports portRanges, interfaceName string) []finding {
	var findings []finding
	for _, state := range collector.instances {
		if state.ServiceType == "" || (state.Port != 0 && !ports.Contains(state.Port)) {
			continue
		}
		addresses := collector.addresses[state.Host]
		if len(addresses) == 0 && state.Source.IsValid() {
			addresses = []addressRecord{{Address: state.Source}}
		}
		filtered := filterAddresses(addresses, cidrs)
		if len(filtered) == 0 {
			continue
		}
		service, _, _ := parseServiceType(state.ServiceType)
		item := finding{
			IP:           filtered[0].Address.String(),
			Transport:    state.Transport,
			Host:         strings.TrimSuffix(state.Host, "."),
			Service:      service,
			Instance:     state.Instance,
			State:        "advertised",
			MetadataOnly: state.Port == 0,
			TTL:          minimumTTL(state.TTLValues, filtered),
			TXTRaw:       append([]string(nil), state.TXT...),
			Fingerprint:  fingerprint(service, state.TXT),
		}
		if state.Port != 0 {
			port := state.Port
			item.Port = &port
		}
		for _, address := range filtered {
			text := address.Address.String()
			if address.Address.Is4() {
				item.IPv4 = append(item.IPv4, text)
			} else {
				item.IPv6 = append(item.IPv6, text+"%"+interfaceName)
			}
		}
		item.Banner = buildBanner(item)
		findings = append(findings, item)
	}
	sortFindings(findings)
	return findings
}

func filterAddresses(records []addressRecord, cidrs []netip.Prefix) []addressRecord {
	filtered := make([]addressRecord, 0, len(records))
	for _, record := range records {
		if containsAddress(cidrs, record.Address) {
			filtered = append(filtered, record)
		}
	}
	sort.Slice(filtered, func(left, right int) bool {
		return filtered[left].Address.Less(filtered[right].Address)
	})
	return filtered
}

func (collector *inventory) sortedServiceTypes() []string {
	services := make([]string, 0, len(collector.serviceTypes))
	for service := range collector.serviceTypes {
		services = append(services, strings.TrimSuffix(service, "."))
	}
	sort.Strings(services)
	return services
}

func parseServiceType(value string) (string, string, bool) {
	parts := strings.Split(strings.TrimSuffix(canonicalName(value), "."), ".")
	if len(parts) < 3 || !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") {
		return "", "", false
	}
	transport := strings.TrimPrefix(parts[1], "_")
	if transport != "tcp" && transport != "udp" {
		return "", "", false
	}
	return strings.TrimPrefix(parts[0], "_"), transport, true
}

func canonicalName(value string) string {
	return strings.ToLower(dns.Fqdn(value))
}

func instanceDisplayName(instance string, serviceType string) string {
	suffix := "." + strings.TrimSuffix(serviceType, ".") + "."
	return strings.TrimSuffix(instance, suffix)
}

func sourceAddress(source net.Addr) netip.Addr {
	udpAddress, ok := source.(*net.UDPAddr)
	if !ok {
		return netip.Addr{}
	}
	address, valid := netip.AddrFromSlice(udpAddress.IP)
	if !valid {
		return netip.Addr{}
	}
	return address.Unmap()
}

func appendUnique(values []string, additions ...string) []string {
	for _, addition := range additions {
		found := false
		for _, value := range values {
			if value == addition {
				found = true
				break
			}
		}
		if !found {
			values = append(values, addition)
		}
	}
	return values
}

func minimumTTL(values []uint32, addresses []addressRecord) uint32 {
	minimum := uint32(0)
	for _, value := range values {
		if value != 0 && (minimum == 0 || value < minimum) {
			minimum = value
		}
	}
	for _, address := range addresses {
		if address.TTL != 0 && (minimum == 0 || address.TTL < minimum) {
			minimum = address.TTL
		}
	}
	return minimum
}

func sortFindings(findings []finding) {
	sort.Slice(findings, func(left, right int) bool {
		leftPort, rightPort := uint16(0), uint16(0)
		if findings[left].Port != nil {
			leftPort = *findings[left].Port
		}
		if findings[right].Port != nil {
			rightPort = *findings[right].Port
		}
		if leftPort != rightPort {
			return leftPort < rightPort
		}
		if findings[left].Service != findings[right].Service {
			return findings[left].Service < findings[right].Service
		}
		return findings[left].Instance < findings[right].Instance
	})
}
