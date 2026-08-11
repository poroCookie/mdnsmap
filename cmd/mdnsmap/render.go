package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
)

func renderText(writer io.Writer, findings []finding, serviceTypes []string) error {
	buffer := bufio.NewWriter(writer)
	defer buffer.Flush()
	if _, err := fmt.Fprintln(buffer, "services:"); err != nil {
		return err
	}
	for _, item := range findings {
		header := item.Service + ":"
		if item.Port != nil {
			header = fmt.Sprintf("%d/%s %s:", *item.Port, item.Transport, item.Service)
		}
		if _, err := fmt.Fprintln(buffer, header); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(buffer, item.Banner); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(buffer, "answers:\nPTR:"); err != nil {
		return err
	}
	for _, serviceType := range serviceTypes {
		if _, err := fmt.Fprintln(buffer, sanitize(serviceType)); err != nil {
			return err
		}
	}
	return nil
}

func renderJSONL(writer io.Writer, findings []finding) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, item := range findings {
		if err := encoder.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func buildBanner(item finding) string {
	lines := []string{"Name=" + sanitize(item.Instance)}
	if len(item.IPv4) > 0 {
		lines = append(lines, "IPv4="+strings.Join(item.IPv4, ","))
	}
	if len(item.IPv6) > 0 {
		lines = append(lines, "IPv6="+strings.Join(item.IPv6, ","))
	}
	if item.Host != "" {
		lines = append(lines, "Hostname="+sanitize(item.Host))
	}
	lines = append(lines, fmt.Sprintf("TTL=%d", item.TTL))
	for _, text := range item.TXTRaw {
		lines = append(lines, sanitize(text))
	}
	return strings.Join(lines, "\n")
}

func fingerprint(service string, rawTXT []string) map[string]string {
	if service != "qdiscover" {
		return nil
	}
	result := make(map[string]string)
	for _, text := range rawTXT {
		for _, part := range strings.Split(text, ",") {
			key, value, found := strings.Cut(part, "=")
			if found {
				result[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
	}
	if result["model"] != "" || result["displayModel"] != "" {
		result["vendor"] = "QNAP"
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func sanitize(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\r' || character == 0x1b ||
			(unicode.IsControl(character) && character != '\t') {
			fmt.Fprintf(&builder, "\\u%04x", character)
			continue
		}
		builder.WriteRune(character)
	}
	return builder.String()
}
