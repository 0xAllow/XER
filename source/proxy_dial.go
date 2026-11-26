package main

import (
	"bufio"
	"context"
	"crypto/tls"
 "crypto/x509"
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
		if half, ok := conn.(interface{CloseWrite()error}); ok {
			_ = half.CloseWrite()
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
func dialHTTPProxy(p *url.URL,target string)(net.Conn,error){return dialHTTPProxyContext(context.Background(),p,target,activeNetwork.Family,nil)}
func dialHTTPProxyContext(ctx context.Context,p *url.URL,target,family string,roots *x509.CertPool)(net.Conn,error){
 host,port,err:=net.SplitHostPort(target);if err!=nil || host=="" || strings.ContainsAny(host,"\r\n\x00 \t"){return nil,errors.New("invalid proxy target")}
 n,err:=strconv.Atoi(port);if err!=nil || n<1 || n>65535{return nil,errors.New("invalid proxy target port")}
 c,err:=dialNetwork(ctx,"tcp",p.Host,family);if err!=nil{return nil,err}
 good:=false
 defer func(){if !good{c.Close()}}()
 rawConn:=c
 stopCancel:=context.AfterFunc(ctx,func(){rawConn.Close()});defer stopCancel()
 deadline:=time.Now().Add(20*time.Second);if d,ok:=ctx.Deadline();ok && d.Before(deadline){deadline=d}
 if err=c.SetDeadline(deadline);err!=nil{return nil,err}
 if p.Scheme=="https" {
  tc:=tls.Client(c,&tls.Config{MinVersion:tls.VersionTLS12,ServerName:p.Hostname(),RootCAs:roots})
  if err=tc.HandshakeContext(ctx);err!=nil{return nil,err};c=tc
 }
 if _,err=fmt.Fprintf(c,"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",target,target);err!=nil{return nil,err}
 rd:=bufio.NewReaderSize(c,4096)
 statusBytes,err:=rd.ReadSlice('\n');if err!=nil{return nil,fmt.Errorf("invalid or oversized proxy status: %w",err)}
 fields:=strings.Fields(string(statusBytes))
 if len(fields)<2 || (fields[0]!="HTTP/1.1" && fields[0]!="HTTP/1.0") || fields[1]!="200"{return nil,errors.New("proxy CONNECT declined")}
 total:=len(statusBytes)
 for {
  line,err:=rd.ReadSlice('\n');if err!=nil{return nil,fmt.Errorf("invalid or oversized proxy header: %w",err)}
  total+=len(line);if total>16384{return nil,errors.New("proxy headers too large")}
  if string(line)=="\r\n"{break}
  if !strings.HasSuffix(string(line),"\r\n") || !strings.Contains(string(line),":"){return nil,errors.New("invalid proxy header")}
 }
 if err=c.SetDeadline(time.Time{});err!=nil{return nil,err}
 good=true;return &bufferedConn{Conn:c,reader:rd},nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *bufferedConn) CloseWrite()error{if half,ok:=b.Conn.(interface{CloseWrite()error});ok{return half.CloseWrite()};return b.Conn.Close()}
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
