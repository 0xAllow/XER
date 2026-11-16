// XER SFTP adapter. Copyright (c) 2026 0xAllow.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Endpoint struct {
	Kind, Target string
	Port         int
}

var endpointName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)
var sshTarget = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*@([a-zA-Z0-9_.-]+|\[[0-9a-fA-F:]+\])$`)

func executable(name string) error {
	_, e := exec.LookPath(name)
	if e != nil {
		return fmt.Errorf("required SSH tool %s not installed: %w", name, e)
	}
	return nil
}
func runExternal(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func sftpQuote(s string) (string, error) {
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("invalid SFTP path")
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`, nil
}
func transferSFTP(ep Endpoint, local, remote string, upload bool) error {
	if err := executable("sftp"); err != nil {
		return err
	}
	a, e := sftpQuote(local)
	if e != nil {
		return e
	}
	b, e := sftpQuote(remote)
	if e != nil {
		return e
	}
	verb := "get"
	if upload {
		verb = "put"
	}
	line := verb + " " + b + " " + a + "\n"
	if upload {
		line = verb + " " + a + " " + b + "\n"
	}
	f, e := os.CreateTemp("", "xer-sftp-*.batch")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.WriteString(line); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	args := []string{"-b", f.Name(), "-P", strconv.Itoa(ep.Port), "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=15"}
	if activeNetwork.Family == "ipv4" {
		args = append(args, "-4")
	} else if activeNetwork.Family == "ipv6" {
		args = append(args, "-6")
	}
	if activeNetwork.Proxy != "" {
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		cmdline, e := sshProxyCommand(exe)
		if e != nil {
			return e
		}
		args = append(args, "-oProxyCommand="+cmdline)
		cmd := exec.Command("sftp", append(args, ep.Target)...)
		cmd.Env = append(os.Environ(), "XER_PROXY_URL="+activeNetwork.Proxy, "XER_PROXY_FAMILY="+activeNetwork.Family)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return runExternal("sftp", append(args, ep.Target)...)
}
func directSFTP(host string, port int) (Endpoint, error) {
	if !sshTarget.MatchString(host) {
		return Endpoint{}, errors.New("SFTP destination must be USER@HOST (IPv6: USER@[ADDRESS])")
	}
	if port == 0 {
		port = 22
	}
	return Endpoint{Kind: "sftp", Target: host, Port: port}, nil
}
func sftpSend(file, host string, port int) error {
	ep, e := directSFTP(host, port)
	if e != nil {
		return e
	}
	st, e := os.Stat(file)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return errors.New("source is not a regular file")
	}
	return transferSFTP(ep, file, filepath.Base(file), true)
}
func sftpGet(source, dest string, port int) error {
	i := strings.LastIndexByte(source, ':')
	if i < 1 || i == len(source)-1 {
		return errors.New("expected USER@HOST:FILE")
	}
	ep, e := directSFTP(source[:i], port)
	if e != nil {
		return e
	}
	remote := source[i+1:]
	if strings.HasPrefix(remote, "-") || strings.ContainsAny(remote, "\r\n\x00") {
		return errors.New("invalid remote path")
	}
	if dest == "" {
		dest = filepath.Base(remote)
	}
	if _, e = os.Lstat(dest); e == nil {
		return errors.New("destination exists (refusing overwrite)")
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	id, e := randomHex(12)
	if e != nil {
		return e
	}
	part := filepath.Join(filepath.Dir(dest), ".xer-"+id+".part")
	defer os.Remove(part)
	if e = transferSFTP(ep, part, remote, false); e != nil {
		return e
	}
	st, e := os.Stat(part)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return errors.New("download is not a regular file")
	}
	return os.Link(part, dest)
}
