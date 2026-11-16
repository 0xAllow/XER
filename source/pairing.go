package main

// Interactive certificate pairing. No shared token or pasted fingerprint.
// Both humans compare the SAME code, derived from the server and client public
// certificates, before the receiver approves the client's identity.

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var pairMu sync.Mutex

func identity() (tls.Certificate, error) {
	d, e := configDir()
	if e != nil {
		return tls.Certificate{}, e
	}
	c, _, e := makeCert(filepath.Join(d, "identity"))
	return c, e
}
func fingerprint(der []byte) string { h := sha256.Sum256(der); return hex.EncodeToString(h[:]) }
func pairCode(serverDER, clientDER []byte) string {
	h := sha256.New()
	h.Write([]byte("xer-pair-v1\x00"))
	h.Write(serverDER)
	h.Write(clientDER)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)[:10]))
}
func confirm(prompt string) bool {
	fmt.Print(prompt, " [type YES]: ")
	var v string
	_, err := fmt.Fscanln(os.Stdin, &v)
	return err == nil && v == "YES"
}
func trustedPath(root string) string { return filepath.Join(root, ".xer-data", "trusted.json") }
func readTrusted(root string) (map[string]bool, error) {
	p := map[string]bool{}
	b, e := os.ReadFile(trustedPath(root))
	if errors.Is(e, os.ErrNotExist) {
		return p, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(b, &p); e != nil {
		return nil, e
	}
	return p, nil
}
func (s *Server) paired(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		return false
	}
	clients, e := readTrusted(s.root)
	if e != nil {
		return false
	}
	return clients[fingerprint(r.TLS.PeerCertificates[0].Raw)]
}
func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		http.Error(w, "client certificate required", 401)
		return
	}
	// Serialize interactive approvals to prevent concurrent prompts.
	pairMu.Lock()
	defer pairMu.Unlock()
	client := r.TLS.PeerCertificates[0]
	if time.Now().Before(client.NotBefore) || time.Now().After(client.NotAfter) {
		http.Error(w, "expired identity", 403)
		return
	}
	cert := s.certDER
	code := pairCode(cert, client.Raw)
	fmt.Printf("\nPairing request from %s\nCompare this code with the sender: %s\n", r.RemoteAddr, code)
	if !confirm("Code matches and approve this device?") {
		http.Error(w, "pairing declined", 403)
		return
	}
	clients, e := readTrusted(s.root)
	if e != nil {
		http.Error(w, "trust database error", 500)
		return
	}
	clients[fingerprint(client.Raw)] = true
	if e = storeJSON(trustedPath(s.root), clients); e != nil {
		http.Error(w, "trust database error", 500)
		return
	}
	w.WriteHeader(204)
	fmt.Println("Device paired.")
}
func address(alias string) (string, error) {
	p, e := loadProfiles()
	if e != nil {
		return "", e
	}
	if saved, ok := p.Servers[alias]; ok {
		return saved.Address, nil
	}
	if strings.Contains(alias, "/") || strings.ContainsAny(alias, "\n\r\x00 ") {
		return "", errors.New("invalid address")
	}
	if _, _, e = net.SplitHostPort(alias); e == nil {
		return alias, nil
	}
	if strings.Contains(alias, ":") {
		return "", errors.New("use HOST:PORT or IPv6 [ADDRESS]:PORT")
	}
	return net.JoinHostPort(alias, strconv.Itoa(activeSettings.Port)), nil
}
func pairAddress(alias string) (Profile, error) {
	adr, e := address(alias)
	if e != nil {
		return Profile{}, e
	}
	id, e := identity()
	if e != nil {
		return Profile{}, e
	}
	var serverPin string
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: []tls.Certificate{id}, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return errors.New("receiver certificate missing")
		}
		c := cs.PeerCertificates[0]
		if time.Now().Before(c.NotBefore) || time.Now().After(c.NotAfter) {
			return errors.New("receiver certificate expired/not yet valid")
		}
		code := pairCode(c.Raw, id.Certificate[0])
		fmt.Printf("\nFirst-time pairing with %s\nCompare with code on the receiver: %s\n", adr, code)
		if !confirm("Do both displays match?") {
			return errors.New("pairing not confirmed")
		}
		serverPin = fingerprint(c.Raw)
		return nil
	}}}
	if e := configureHTTPTransport(tr); e != nil {
		return Profile{}, e
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("redirect forbidden") }}
	resp, e := client.Post("https://"+adr+"/v1/pair", "application/octet-stream", nil)
	if e != nil {
		return Profile{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		return Profile{}, fmt.Errorf("pairing rejected (HTTP %d)", resp.StatusCode)
	}
	p := Profile{Address: adr, Fingerprint: serverPin}
	all, e := loadProfiles()
	if e != nil {
		return Profile{}, e
	}
	all.Servers[alias] = p
	path, e := configFile()
	if e != nil {
		return Profile{}, e
	}
	if e = storeJSON(path, all); e != nil {
		return Profile{}, e
	}
	fmt.Println("Trusted device saved.")
	return p, nil
}
func getOrPair(alias string) (Profile, error) {
	all, e := loadProfiles()
	if e != nil {
		return Profile{}, e
	}
	if p, ok := all.Servers[alias]; ok {
		return p, nil
	}
	return pairAddress(alias)
}
func clientIdentityTLS(c *tls.Config) error {
	id, e := identity()
	if e != nil {
		return e
	}
	c.Certificates = []tls.Certificate{id}
	return nil
}
func certValid(c *x509.Certificate) error {
	if time.Now().Before(c.NotBefore) || time.Now().After(c.NotAfter) {
		return errors.New("certificate not valid at this time")
	}
	return nil
}

// ensure imports stay checked by the compiler.
var _ = bufio.ErrInvalidUnreadByte

func trustCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xer trust list|remove FINGERPRINT (run from receiver folder)")
	}
	root, e := filepath.Abs(".")
	if e != nil {
		return e
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: xer trust list")
		}
		t, e := readTrusted(root)
		if e != nil {
			return e
		}
		for fp := range t {
			fmt.Println(fp)
		}
		return nil
	case "remove":
		if len(args) != 2 || !goodHash(args[1]) {
			return errors.New("usage: xer trust remove CLIENT_FINGERPRINT")
		}
		t, e := readTrusted(root)
		if e != nil {
			return e
		}
		delete(t, strings.ToLower(args[1]))
		return storeJSON(trustedPath(root), t)
	default:
		return errors.New("usage: xer trust list|remove FINGERPRINT")
	}
}

func localLANAddresses() []string {
	var found []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return found
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, e := iface.Addrs()
		if e != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, e := net.ParseCIDR(a.String())
			if e == nil && ip.To4() != nil && ip.IsPrivate() {
				found = append(found, ip.String())
			}
		}
	}
	return found
}
