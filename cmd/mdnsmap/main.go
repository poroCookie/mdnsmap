package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"
)

type cidrFlags []netip.Prefix

func (flags *cidrFlags) String() string { return fmt.Sprint(*flags) }

func (flags *cidrFlags) Set(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return fmt.Errorf("无效 CIDR %q: %w", value, err)
	}
	*flags = append(*flags, prefix.Masked())
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) > 0 && arguments[0] == "scan" {
		arguments = arguments[1:]
	}

	flags := flag.NewFlagSet("mdnsmap scan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var cidrs cidrFlags
	flags.Var(&cidrs, "cidr", "目标 CIDR，可重复")
	portsText := flags.String("ports", "1-65535", "SRV 端口过滤表达式")
	interfaceName := flags.String("interface", "", "扫描网卡，默认按 CIDR 自动选择")
	timeout := flags.Duration("timeout", 8*time.Second, "扫描时长")
	format := flags.String("format", "text", "输出格式：text 或 jsonl")
	strictHopLimit := flags.Bool("strict-hop-limit", true, "仅接受 Hop Limit/TTL 为 255 的响应")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if len(cidrs) == 0 {
		return errors.New("至少需要一个 --cidr")
	}
	if *timeout <= 0 {
		return errors.New("--timeout 必须大于 0")
	}
	if *format != "text" && *format != "jsonl" {
		return errors.New("--format 仅支持 text 或 jsonl")
	}

	ports, err := parsePortRanges(*portsText)
	if err != nil {
		return err
	}
	config := scanConfig{
		CIDRs:         cidrs,
		Ports:         ports,
		InterfaceName: *interfaceName,
		Timeout:       *timeout,
		StrictTTL:     *strictHopLimit,
	}
	findings, serviceTypes, err := scan(config)
	if err != nil {
		return err
	}
	if *format == "jsonl" {
		return renderJSONL(os.Stdout, findings)
	}
	return renderText(os.Stdout, findings, serviceTypes)
}
