package main

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

func TestHTTPConnectTunnel(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		rd := bufio.NewReader(c)
		request, e := rd.ReadString('\n')
		if e != nil {
			done <- e
			return
		}
		if !strings.Contains(request, "CONNECT remote.example:22 HTTP/1.1") {
			done <- io.ErrUnexpectedEOF
			return
		}
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, e = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-TEST\r\n"))
		done <- e
	}()
	p, e := validatedProxy("http://" + ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	c, e := dialHTTPProxy(p, "remote.example:22")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	got := make([]byte, 12)
	if _, e = io.ReadFull(c, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != "SSH-2.0-TEST" {
		t.Fatal("tunnel lost buffered bytes")
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestSSHProxyCommand(t *testing.T) {
	got, e := sshProxyCommand("/tmp/XER program/xer")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(got, "proxy-dial %h %p") {
		t.Fatalf("invalid command %s", got)
	}
}
