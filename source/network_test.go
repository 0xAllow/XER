package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParallelHTTPSChunks(t *testing.T) {
	root, _, _, _ := testReceiver(t)
	source := filepath.Join(t.TempDir(), "parallel.bin")
	original := bytes.Repeat([]byte("parallel encrypted test contents"), 300000)
	if e := os.WriteFile(source, original, 0600); e != nil {
		t.Fatal(e)
	}
	if e := sendFileWithOptions(source, "local", 256*1024, 4); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(filepath.Join(root, "parallel.bin"))
	if e != nil || !bytes.Equal(got, original) {
		t.Fatalf("parallel output mismatch: %v", e)
	}
}
func TestProxyValidation(t *testing.T) {
	for _, bad := range []string{"http://user:secret@localhost:8080", "ftp://localhost:21", "http://localhost", "socks5h://localhost:0", "socks5h://localhost:1080/path"} {
		if _, e := validatedProxy(bad); e == nil {
			t.Fatalf("accepted invalid proxy %q", bad)
		}
	}
	for _, good := range []string{"socks5h://127.0.0.1:9050", "https://proxy.example:443", "http://proxy.example:3128"} {
		if _, e := validatedProxy(good); e != nil {
			t.Fatalf("rejected %s: %v", good, e)
		}
	}
}
func TestSOCKSRemoteDNSAndReject(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		greeting := make([]byte, 3)
		if _, e = io.ReadFull(c, greeting); e != nil {
			done <- e
			return
		}
		if !bytes.Equal(greeting, []byte{5, 1, 0}) {
			done <- errors.New("invalid greeting")
			return
		}
		c.Write([]byte{5, 0})
		header := make([]byte, 5)
		if _, e = io.ReadFull(c, header); e != nil {
			done <- e
			return
		}
		if header[3] != 3 {
			done <- errors.New("remote DNS not used")
			return
		}
		rest := make([]byte, int(header[4])+2)
		if _, e = io.ReadFull(c, rest); e != nil {
			done <- e
			return
		}
		if string(rest[:len(rest)-2]) != "hidden.example" {
			done <- errors.New("wrong remote name")
			return
		}
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		done <- nil
	}()
	if _, e = dialSOCKS5(context.Background(), listener.Addr().String(), "hidden.example:8443"); e == nil {
		t.Fatal("proxy reject should fail closed")
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestNetworkOptions(t *testing.T) {
	in, reset, e := extractNetworkArgs([]string{"--ipv4", "--proxy", "socks5h://127.0.0.1:9050", "a", "--via", "https"})
	if e != nil {
		t.Fatal(e)
	}
	if activeNetwork.Family != "ipv4" || activeNetwork.Proxy == "" || len(in) != 3 {
		t.Fatalf("invalid selection: %+v %v", activeNetwork, in)
	}
	reset()
	if activeNetwork.Proxy != "" {
		t.Fatal("proxy not reset")
	}
	if _, _, e := extractNetworkArgs([]string{"--ipv4", "--ipv6"}); e == nil {
		t.Fatal("accepted both IP families")
	}
}
func TestDirectSFTP(t *testing.T) {
	if _, e := directSFTP("admin@example.com", 22); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"bad;command", "admin@example.com -oEvil", "admin@"} {
		if _, e := directSFTP(s, 22); e == nil {
			t.Fatalf("unsafe SFTP target allowed %q", s)
		}
	}
}
