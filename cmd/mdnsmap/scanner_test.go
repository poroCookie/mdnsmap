package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestInventoryBuildsDeepBannerAndKeepsDuplicatePorts(t *testing.T) {
	collector := newInventory()
	message := new(dns.Msg)
	message.Answer = []dns.RR{
		mustRR(t, "_http._tcp.local. 10 IN PTR slw-nas._http._tcp.local."),
		mustRR(t, "_qdiscover._tcp.local. 10 IN PTR slw-nas._qdiscover._tcp.local."),
	}
	message.Extra = []dns.RR{
		mustRR(t, "slw-nas._http._tcp.local. 10 IN SRV 0 0 5000 slw-nas.local."),
		mustRR(t, "slw-nas._http._tcp.local. 10 IN TXT \"path=/\""),
		mustRR(t, "slw-nas._qdiscover._tcp.local. 10 IN SRV 0 0 5000 slw-nas.local."),
		mustRR(t, "slw-nas._qdiscover._tcp.local. 10 IN TXT \"accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214\""),
		mustRR(t, "slw-nas.local. 10 IN A 192.0.2.10"),
		mustRR(t, "slw-nas.local. 10 IN AAAA fe80::265e:beff:fe69:a313"),
	}
	collector.ingest(message, netip.MustParseAddr("192.0.2.10"), func(string, ...uint16) {})

	findings := collector.buildFindings(
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("fe80::/64")},
		portRanges{{Start: 5000, End: 5000}},
		"en0",
	)
	if len(findings) != 2 {
		t.Fatalf("期望保留同端口两个服务，实际得到 %d", len(findings))
	}
	var output bytes.Buffer
	if err := renderText(&output, findings, collector.sortedServiceTypes()); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{
		"5000/tcp http:",
		"path=/",
		"5000/tcp qdiscover:",
		"displayModel=TS-464C",
		"Hostname=slw-nas.local",
		"IPv6=fe80::265e:beff:fe69:a313%en0",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("输出缺少 %q\n%s", expected, text)
		}
	}
	if findings[1].Fingerprint["vendor"] != "QNAP" {
		t.Fatalf("未识别 QNAP 指纹: %#v", findings[1].Fingerprint)
	}
}

func TestParsePortRanges(t *testing.T) {
	ranges, err := parsePortRanges("445,5000-5100")
	if err != nil {
		t.Fatal(err)
	}
	if !ranges.Contains(445) || !ranges.Contains(5050) || ranges.Contains(80) {
		t.Fatalf("端口范围解析错误: %#v", ranges)
	}
}

func mustRR(t *testing.T, value string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(value)
	if err != nil {
		t.Fatalf("构造 DNS 记录失败: %v", err)
	}
	return record
}
