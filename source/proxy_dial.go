package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Internal OpenSSH ProxyCommand helper. Only a validated, explicitly chosen
// proxy is used. Stdout carries tunnel bytes exclusively (no logging).
func proxyDialCommand(args []string) error {
	if len(args) != 2 {
		return errors.New("internal proxy helper requires HOST PORT")
	}
	target := net.JoinHostPort(args[0], args[1])
	if _, e := strconv.Atoi(args[1]); e != nil {
		return errors.New("invalid port")
	}
	activeNetwork.Family = os.Getenv("XER_PROXY_FAMILY")
	raw := os.Getenv("XER_PROXY_URL")
	p, e := validatedProxy(raw)
	if e != nil {
		return e
	}
	if p == nil {
		return errors.New("missing proxy in helper environment")
	}
	var conn net.Conn
	switch p.Scheme {
	case "socks5", "socks5h":
		conn, e = dialSOCKS5(context.Background(), p.Host, target)
	case "http", "https":
		conn, e = dialHTTPProxy(p, target)
	default:
		e = errors.New("unknown proxy")
	}
	if e != nil {
		return e
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_, e := io.Copy(conn, os.Stdin)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- e
	}()
	_, e = io.Copy(os.Stdout, conn)
	// The stdin copier may block if OpenSSH aborted; process exits and closes it.
	if e != nil {
		return e
	}
	return nil
}
func dialHTTPProxy(p *url.URL, target string) (net.Conn, error) {
	c, e := dialNetwork(context.Background(), "tcp", p.Host, activeNetwork.Family)
	if e != nil {
		return nil, e
	}
	good := false
	defer func() {
		if !good {
			c.Close()
		}
	}()
	if p.Scheme == "https" {
		tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: p.Hostname()})
		if e = tc.Handshake(); e != nil {
			return nil, e
		}
		c = tc
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	// Headers contain only validated hostnames and numeric ports.
	if strings.ContainsAny(target, "\r\n") {
		return nil, errors.New("invalid target")
	}
	if _, e = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", target, target); e != nil {
		return nil, e
	}
	rd := bufio.NewReader(c)
	status, e := rd.ReadString('\n')
	if e != nil {
		return nil, e
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200 ") && !strings.HasPrefix(status, "HTTP/1.0 200 ") {
		return nil, fmt.Errorf("proxy CONNECT declined: %s", strings.TrimSpace(status))
	}
	total := len(status)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		total += len(line)
		if total > 16384 {
			return nil, errors.New("proxy headers too large")
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	c.SetDeadline(time.Time{})
	good = true
	// bufio.Reader may have prefetched part of the SSH handshake.
	return &bufferedConn{Conn: c, reader: rd}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.reader.Read(p) }
func sshProxyCommand(exe string) (string, error) {
	if strings.ContainsAny(exe, "\r\n\x00") {
		return "", errors.New("invalid executable path")
	}
	if runtime.GOOS == "windows" {
		if strings.Contains(exe, `"`) || strings.Contains(exe, "%") {
			return "", errors.New("unsafe executable path for Windows ProxyCommand")
		}
		return `"` + filepath.Clean(exe) + `" proxy-dial %h %p`, nil
	}
	// Shell quoting for OpenSSH ProxyCommand, which is executed by a shell.
	quoted := "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
	return quoted + " proxy-dial %h %p", nil
}
