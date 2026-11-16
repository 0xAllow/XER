package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Network preferences affect only an explicitly selected transport. An
// explicitly requested proxy is never replaced with a direct connection.
type networkOptions struct {
	Proxy  string
	Family string
}

var activeNetwork networkOptions

type settings struct {
	Port     int
	Chunk    int64
	Parallel int
	Proxy    string
}

func defaultSettings() settings { return settings{Port: 8443, Chunk: 1024 * 1024, Parallel: 1} }

// Restrained TOML reader: known [network] and [transfer] scalar keys only.
// No embedded secrets. The optional file always lives next to the binary.
func readSettings() (settings, error) {
	s := defaultSettings()
	exe, e := os.Executable()
	if e != nil {
		return s, e
	}
	raw, e := os.ReadFile(filepath.Join(filepath.Dir(exe), "config.toml"))
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if len(raw) > 65536 {
		return s, errors.New("config.toml too large")
	}
	section := ""
	seen := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section != "network" && section != "transfer" {
				return s, fmt.Errorf("config.toml line %d: unsupported section", i+1)
			}
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return s, fmt.Errorf("config.toml line %d: expected key=value", i+1)
		}
		key := section + "." + strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if seen[key] {
			return s, fmt.Errorf("config.toml: duplicate %s", key)
		}
		seen[key] = true
		v = strings.Trim(v, "\"")
		switch key {
		case "network.port":
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 65535 {
				return s, errors.New("invalid network.port")
			}
			s.Port = n
		case "network.proxy":
			if _, e := validatedProxy(v); e != nil {
				return s, e
			}
			s.Proxy = v
		case "transfer.chunk":
			n, e := parseChunk(v)
			if e != nil {
				return s, e
			}
			s.Chunk = n
		case "transfer.parallel":
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 8 {
				return s, errors.New("parallel must be 1..8")
			}
			s.Parallel = n
		default:
			return s, fmt.Errorf("unknown config.toml setting %s", key)
		}
	}
	return s, nil
}
func parseChunk(v string) (int64, error) {
	v = strings.ToUpper(v)
	v = strings.TrimSuffix(v, "IB")
	v = strings.TrimSuffix(v, "B")
	mult := int64(1)
	if strings.HasSuffix(v, "M") {
		mult = 1024 * 1024
		v = strings.TrimSuffix(v, "M")
	}
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil || n < 1 || n > maxChunk/mult {
		return 0, errors.New("chunk size must be 1B..64MiB")
	}
	return n * mult, nil
}
func validatedProxy(p string) (*url.URL, error) {
	if p == "" {
		return nil, nil
	}
	u, e := url.Parse(p)
	if e != nil || u.User != nil || u.Hostname() == "" {
		return nil, errors.New("invalid proxy address (credentials in URLs forbidden)")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, errors.New("proxy must be http, https, socks5 or socks5h")
	}
	if u.Port() == "" {
		return nil, errors.New("proxy requires explicit port")
	}
	n, e := strconv.Atoi(u.Port())
	if e != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid proxy port")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("proxy URL must not contain path/query/fragment")
	}
	return u, nil
}
func configureHTTPTransport(t *http.Transport) error {
	p, e := validatedProxy(activeNetwork.Proxy)
	if e != nil {
		return e
	}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialNetwork(ctx, network, addr, activeNetwork.Family)
	}
	if p == nil {
		t.Proxy = nil
		return nil
	}
	if p.Scheme == "socks5" || p.Scheme == "socks5h" {
		// SOCKS5h always forwards names to the proxy. No local target DNS lookup.
		t.Proxy = nil
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialSOCKS5(ctx, p.Host, addr)
		}
		return nil
	}
	t.Proxy = http.ProxyURL(p)
	return nil
}
func dialNetwork(ctx context.Context, network, addr, family string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second, FallbackDelay: 200 * time.Millisecond}
	switch family {
	case "ipv4":
		return d.DialContext(ctx, "tcp4", addr)
	case "ipv6":
		return d.DialContext(ctx, "tcp6", addr)
	}
	return d.DialContext(ctx, network, addr)
}
func dialSOCKS5(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	conn, e := dialNetwork(ctx, "tcp", proxyAddr, activeNetwork.Family)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	if _, e = conn.Write([]byte{5, 1, 0}); e != nil {
		return nil, e
	}
	resp := make([]byte, 2)
	if _, e = io.ReadFull(conn, resp); e != nil {
		return nil, e
	}
	if resp[0] != 5 || resp[1] != 0 {
		return nil, errors.New("SOCKS5 proxy requires unsupported authentication")
	}
	host, portStr, e := net.SplitHostPort(target)
	if e != nil {
		return nil, e
	}
	port, e := strconv.Atoi(portStr)
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid destination port")
	}
	request := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		request = append(request, 1)
		request = append(request, ip.To4()...)
	} else if ip != nil {
		request = append(request, 4)
		request = append(request, ip.To16()...)
	} else {
		if len(host) < 1 || len(host) > 255 {
			return nil, errors.New("invalid SOCKS hostname")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	request = append(request, pb[:]...)
	if _, e = conn.Write(request); e != nil {
		return nil, e
	}
	hdr := make([]byte, 4)
	if _, e = io.ReadFull(conn, hdr); e != nil {
		return nil, e
	}
	if hdr[0] != 5 || hdr[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 connect rejected (code %d)", hdr[1])
	}
	var count int
	switch hdr[3] {
	case 1:
		count = 4
	case 4:
		count = 16
	case 3:
		var b [1]byte
		if _, e = io.ReadFull(conn, b[:]); e != nil {
			return nil, e
		}
		count = int(b[0])
	default:
		return nil, errors.New("invalid SOCKS5 response")
	}
	_, e = io.CopyN(io.Discard, conn, int64(count+2))
	if e != nil {
		return nil, e
	}
	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}

var activeSettings = defaultSettings()
var activeSFTPPort int

func extractNetworkArgs(args []string) ([]string, func(), error) {
	oldNet, oldPort := activeNetwork, activeSFTPPort
	reset := func() { activeNetwork = oldNet; activeSFTPPort = oldPort }
	result := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--proxy":
			i++
			if i >= len(args) {
				reset()
				return nil, reset, errors.New("--proxy requires URL")
			}
			if _, e := validatedProxy(args[i]); e != nil {
				reset()
				return nil, reset, e
			}
			activeNetwork.Proxy = args[i]
		case "--no-proxy":
			activeNetwork.Proxy = ""
		case "--ipv4":
			if activeNetwork.Family == "ipv6" {
				reset()
				return nil, reset, errors.New("choose IPv4 or IPv6")
			}
			activeNetwork.Family = "ipv4"
		case "--ipv6":
			if activeNetwork.Family == "ipv4" {
				reset()
				return nil, reset, errors.New("choose IPv4 or IPv6")
			}
			activeNetwork.Family = "ipv6"
		case "--port":
			i++
			if i >= len(args) {
				reset()
				return nil, reset, errors.New("--port requires number")
			}
			n, e := strconv.Atoi(args[i])
			if e != nil || n < 1 || n > 65535 {
				reset()
				return nil, reset, errors.New("port must be 1..65535")
			}
			activeSFTPPort = n // HTTPS per-command port is accepted when destination includes HOST:PORT.
		default:
			result = append(result, args[i])
		}
	}
	return result, reset, nil
}
