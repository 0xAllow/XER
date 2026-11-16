// Trusted HTTPS DNS diagnostic. DNS is NOT a file-transfer protocol.
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type dnsAnswer struct {
	Data string `json:"data"`
	Type int    `json:"type"`
}
type dnsResult struct {
	Status int         `json:"Status"`
	Answer []dnsAnswer `json:"Answer"`
}

func dnsCommand(args []string) error {
	filtered, reset, err := extractNetworkArgs(args)
	if err != nil {
		return err
	}
	defer reset()
	args = filtered
	if len(args) != 1 {
		return errors.New("usage: xer dns HOSTNAME (DNS-over-HTTPS diagnostic, not file transfer)")
	}
	h := args[0]
	if len(h) > 253 || h == "" || strings.ContainsAny(h, "/:\\\r\n\x00 ") {
		return errors.New("invalid DNS hostname")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid DNS hostname label")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	if err := configureHTTPTransport(transport); err != nil {
		return err
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("DNS redirect forbidden") }}
	found := false
	for _, kind := range []string{"A", "AAAA"} {
		u := "https://dns.google/resolve?" + url.Values{"name": {h}, "type": {kind}}.Encode()
		req, e := http.NewRequest("GET", u, nil)
		if e != nil {
			return e
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, e := client.Do(req)
		if e != nil {
			return fmt.Errorf("DNS-over-HTTPS failed: %w", e)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("DNS-over-HTTPS returned HTTP %d", resp.StatusCode)
		}
		var result dnsResult
		e = json.NewDecoder(io.LimitReader(resp.Body, 65537)).Decode(&result)
		resp.Body.Close()
		if e != nil {
			return e
		}
		if result.Status != 0 {
			continue
		}
		for _, a := range result.Answer {
			ip := net.ParseIP(a.Data)
			if ip == nil {
				continue
			}
			if kind == "A" && ip.To4() == nil || kind == "AAAA" && ip.To4() != nil {
				continue
			}
			fmt.Printf("%s\t%s\n", kind, ip.String())
			found = true
		}
	}
	if !found {
		return errors.New("no A/AAAA records found")
	}
	return nil
}
