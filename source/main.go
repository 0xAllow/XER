// XER: encrypted, chunked, resumable file transfers.
// Copyright (c) 2026 0xAllow. MIT License.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "0.0.1-dev"
const chunkSize int64 = 1024 * 1024
const maxChunk int64 = 64 * 1024 * 1024
const headerToken = "Authorization"

type Profile struct {
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
}
type Profiles struct {
	Servers map[string]Profile `json:"servers"`
}
type Upload struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Size      int64            `json:"size"`
	ChunkSize int64            `json:"chunk_size"`
	SHA256    string           `json:"sha256"`
	Received  map[int64]string `json:"received"`
}
type InitRequest struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ChunkSize int64  `json:"chunk_size"`
	SHA256    string `json:"sha256"`
}
type InitResponse struct {
	ID string `json:"id"`
}
type Server struct {
	root    string
	token   string
	certDER []byte
	mu      sync.Mutex
	initOnce sync.Once
	slots chan struct{}
	limits receiverLimits
	pairingUntil time.Time
 pairMu sync.Mutex
 pairCount int
	uploadLocks sync.Map
 cacheMu sync.Mutex
 digests map[string]cachedDigest
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xer:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
 if len(args)>0 {switch args[0] {case "help","--help","-h": usage();return nil;case "version","--version","-v":fmt.Println("XER",version);return nil}}
 if len(args)==2 && args[0]!="serve" && (args[1]=="--help" || args[1]=="-h") {usage();return nil}
	cfg, cfgErr := readSettings()
	if cfgErr != nil {
		return cfgErr
	}
	activeSettings = cfg
	activeNetwork = networkOptions{Proxy: cfg.Proxy}
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage()
		return nil
	case "version", "--version", "-v":
		fmt.Println("XER", version)
		return nil
	case "auto":
		return automation(args[1:])
	case "dns":
		return dnsCommand(args[1:])
	case "serve":
		return serveCommand(args[1:])
	case "send":
		return dispatchSend(args[1:])
	case "get":
		return dispatchGet(args[1:])
	case "proxy-dial":
		return proxyDialCommand(args[1:])
	case "trust":
		return trustCommand(args[1:])
	case "doctor":
		return doctor()
	default:
		return fmt.Errorf("unknown command %q (run xer help)", args[0])
	}
}
func usage() {
	fmt.Printf(`XER v%s - Secure File Transfer
Author: 0xAllow
Choose the transport. Trust the connection. Transfer securely.

USAGE
  xer <command> [arguments] [options]

COMMANDS
  serve         Start secure receiver
  send          Send file
  get           Receive file
  auto          Manage YAML automation
  dns           Secure DNS lookup
  trust         Approve, list or revoke device trust; forget receiver profiles
  doctor        Show local configuration status

OPTIONS
  --via         https | sftp (manual; required for transfers)
  --port        SSH port (HTTPS uses HOST:PORT)
  --proxy       http:// | https:// | socks5h://
  --no-proxy    Ignore configured proxy
  --ipv4        Force IPv4
  --ipv6        Force IPv6
  --chunk       Encrypted HTTPS chunk size (up to 64M)
  --parallel    HTTPS upload workers (1-8)
  -h, --help    Help
  -v           Version

EXAMPLES
  xer serve --pair-window 5m
  xer send file.txt 192.168.1.102 --via https
  xer get 192.168.1.102:file.txt --via https
  xer send file.txt admin@server --via sftp
  xer send file.txt server --via https --proxy socks5h://127.0.0.1:9050
  xer send backup.zip server --via https --chunk 4M --parallel 4
  xer dns example.com
  xer auto add backup.yaml
  xer auto run backup

ADVANCED
  xer trust list | remove FINGERPRINT
  xer auto list | remove NAME | install | uninstall | tick
`, version)
}
var userConfigDir = os.UserConfigDir
var userCacheDir = os.UserCacheDir

func configDir() (string, error) {
	p, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(p, "xer"), nil
}
func configFile() (string, error) {
	d, e := configDir()
	return filepath.Join(d, "connections.json"), e
}
func loadProfiles() (Profiles, error) {
	p := Profiles{Servers: map[string]Profile{}}
	file, err := configFile()
	if err != nil {
		return p, err
	}
	b, err := readPrivate(file, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Servers == nil { p.Servers=map[string]Profile{} }; for _,profile:=range p.Servers {if !goodHash(profile.Fingerprint){return p,errors.New("invalid receiver profile fingerprint")};host,port,e:=net.SplitHostPort(profile.Address);if e!=nil{return p,e};n,e:=strconv.Atoi(port);if e!=nil || host=="" || n<1 || n>65535 || strings.ContainsAny(host,"/\\\r\n\x00 \t@?#"){return p,errors.New("invalid receiver profile address")}}
	return p, nil
}
func storeJSON(path string, v any) error {
	if err := privateDir(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xer-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = protectPath(tmp.Name(), false); err != nil { tmp.Close(); return err }
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil { return err }; return syncDirectory(filepath.Dir(path))
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func optionalToken() (string, error) {
 if os.Getenv("XER_TOKEN")=="" && os.Getenv("XER_TOKEN_FILE")=="" { return "",nil }; return tokenValue()
}
func tokenValue() (string, error) {
	if s := strings.TrimSpace(os.Getenv("XER_TOKEN")); s != "" {
		return s, nil
	}
	if f := os.Getenv("XER_TOKEN_FILE"); f != "" {
		st, err := os.Stat(f)
		if err != nil {
			return "", err
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
			return "", errors.New("token file permissions must be owner-only (chmod 600)")
		}
		b, err := readPrivate(f, 65536)
		if err != nil {
			return "", err
		}
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	return "", errors.New("set XER_TOKEN or XER_TOKEN_FILE to a shared secret")
}
func validName(name string) bool {
 base:=strings.TrimRight(strings.ToUpper(strings.SplitN(name,".",2)[0])," ."); if base=="CON" || base=="PRN" || base=="AUX" || base=="NUL" || base=="CONIN$" || base=="CONOUT$" {return false}; for _,prefix:=range []string{"COM","LPT"} { if strings.HasPrefix(base,prefix) && strings.Contains("123456789¹²³",strings.TrimPrefix(base,prefix)) && len([]rune(strings.TrimPrefix(base,prefix)))==1 {return false} }
	if name == "" || name == "." || name == ".." || len(name) > 220 || strings.HasPrefix(strings.ToLower(name), ".xer-") || strings.ContainsAny(name, "/\\<>:\"|?*\x00") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for _, r := range name {
		if r < 32 {
			return false
		}
	}
	return true
}
func goodHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func shaFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func makeCert(dir string) (tls.Certificate, string, error) {
	certPath := filepath.Join(dir, "receiver.crt")
	keyPath := filepath.Join(dir, "receiver.key")
	if err := privateDir(dir); err != nil {return tls.Certificate{},"",err}
	identityLock,err := acquireLock(filepath.Join(dir,"identity.lock")); if err != nil {return tls.Certificate{},"",err}; defer identityLock.Close()
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(keyPath); e == nil {
			return tls.Certificate{}, "", errors.New("private key exists without certificate")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return tls.Certificate{}, "", err
		}
		template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "XER Secure Receiver"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		private, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		if err := writeExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})); err != nil {
			return tls.Certificate{}, "", err
		}
		if err := writeExclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return tls.Certificate{}, "", err
		}
	} else if err != nil {
		return tls.Certificate{}, "", err
	}
	certPEM,err := readPrivate(certPath,65536);if err != nil {return tls.Certificate{},"",err}
	keyPEM,err := readPrivate(keyPath,65536);if err != nil {return tls.Certificate{},"",err}
	cert, err := tls.X509KeyPair(certPEM,keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	parsed,err := x509.ParseCertificate(cert.Certificate[0]);if err != nil {return tls.Certificate{},"",err};if err=certValid(parsed);err!=nil {return tls.Certificate{},"",fmt.Errorf("identity certificate expired; rotate identity and pair again: %w",err)}
	fp := sha256.Sum256(cert.Certificate[0])
	return cert, hex.EncodeToString(fp[:]), nil
}
func serveCommand(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := f.String("dir", ".", "destination folder")
	listen := f.String("listen", fmt.Sprintf(":%d", activeSettings.Port), "bind address")
	maxFile := f.Int64("max-file-size",64<<30,"maximum file size in bytes")
	maxStorage := f.Int64("max-storage",128<<30,"published plus pending bytes quota")
	maxPending := f.Int("max-pending",128,"maximum incomplete uploads")
	maxConcurrent := f.Int("max-concurrent",8,"maximum concurrent authenticated requests")
	pairWindow := f.Duration("pair-window", 0, "accept new pairing sessions for at most 10m (disabled by default)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err,flag.ErrHelp){return nil};return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected serve arguments")
	}
	token, tokenErr := optionalToken()
	if tokenErr != nil { return tokenErr }
	root, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if *pairWindow < 0 || *pairWindow > 10*time.Minute { return errors.New("pair-window must be 0..10m") }
	if err := trustedDirectory(root); err != nil { return err }
	state := filepath.Join(root, ".xer-data")
	receiverLock, err := acquireLock(filepath.Join(state,"receiver.lock")); if err != nil { return err }; defer receiverLock.Close()
	cert, fp, err := makeCert(state)
	if err != nil {
		return err
	}
	if *maxFile<1 || *maxStorage<*maxFile || *maxPending<1 || *maxPending>1024 || *maxConcurrent<1 || *maxConcurrent>64 {return errors.New("invalid receiver limits")}
	srv := &Server{root: root, token: token, certDER: cert.Certificate[0],limits:receiverLimits{MaxFile:*maxFile,MaxStorage:*maxStorage,MaxPending:*maxPending,Concurrent:*maxConcurrent}}
	if err=srv.recoverState();err!=nil{return err}
	if *pairWindow>0 { srv.pairingUntil=time.Now().Add(*pairWindow) }
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pair", srv.pair)
	mux.HandleFunc("/v1/pair/", srv.pairAction)
	mux.HandleFunc("/v1/uploads", srv.auth(srv.uploadInit))
	mux.HandleFunc("/v1/uploads/", srv.auth(srv.uploadAction))
	mux.HandleFunc("/v1/files/", srv.auth(srv.download))
	server := &http.Server{Addr: *listen, Handler: srv.limitResponse(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2*time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert}}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Println("XER receiver listening on", ln.Addr())
	for _, addr := range localLANAddresses() {
		fmt.Println("LAN receiver:", net.JoinHostPort(addr, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)))
	}
	_ = fp
	fmt.Println("Pairing requires an explicit --pair-window and local xer trust approve SESSION CODE.")
	return server.Serve(tls.NewListener(&boundedListener{Listener:ln,slots:make(chan struct{},64)}, server.TLSConfig))
}
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.initLimits()
		select { case s.slots<-struct{}{}: defer func(){<-s.slots}(); default: http.Error(w,"receiver busy",503); return }
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(s.limits.BodyTimeout))
		w.Header().Set("Cache-Control", "no-store")
		provided := strings.TrimPrefix(r.Header.Get(headerToken), "Bearer ")
		if !s.paired(r) && (s.token == "" || len(provided) != len(s.token) || !secureEqual(provided, s.token)) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
func secureEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func readJSON(r *http.Request,v any)error{
 defer r.Body.Close()
 data,err:=io.ReadAll(io.LimitReader(r.Body,(1<<16)+1));if err!=nil{return err};if len(data)>1<<16{return errors.New("JSON body exceeds size limit")}
 d:=json.NewDecoder(bytes.NewReader(data));d.DisallowUnknownFields();if err=d.Decode(v);err!=nil{return err}
 var extra any;if err=d.Decode(&extra);err!=io.EOF{return errors.New("trailing or invalid JSON data")};return nil
}
func (s *Server) statePath(id string) string { return filepath.Join(s.root, ".xer-data", id+".json") }
func (s *Server) partPath(id string) string  { return filepath.Join(s.root, ".xer-data", id+".part") }
func (s *Server) loadUpload(id string) (Upload, error) {
	var u Upload
	b, e := readPrivate(s.statePath(id), 8<<20)
	if e != nil {
		return u, e
	}
	e = json.Unmarshal(b, &u)
	if e==nil { e=s.validateUpload(u,id) }
	return u, e
}
func (s *Server) uploadInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req InitRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	req.SHA256=strings.ToLower(req.SHA256)
	s.initLimits()
	if !validName(req.Name) || req.Size < 0 || req.Size>s.limits.MaxFile || req.ChunkSize <= 0 || req.ChunkSize > maxChunk || !goodHash(req.SHA256) || chunkCount(req.Size,req.ChunkSize)>s.limits.MaxChunks {
		http.Error(w, "invalid upload metadata", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Lstat(filepath.Join(s.root, req.Name)); err == nil {
		http.Error(w, "destination already exists", 409)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "destination unavailable", 500)
		return
	}
	if err := s.reserveUpload(req.Size); err != nil { http.Error(w,err.Error(),507); return }
	id, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	p, err := openPrivate(s.partPath(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		http.Error(w, "storage error", 500)
		return
	}
	if err=p.Close();err!=nil{_ = os.Remove(s.partPath(id));http.Error(w,"part creation failed",500);return}
	u := Upload{ID: id, Name: req.Name, Size: req.Size, ChunkSize: req.ChunkSize, SHA256: req.SHA256, Received: map[int64]string{}}
	if err := storeJSON(s.statePath(id), u); err != nil {
		os.Remove(s.partPath(id))
		http.Error(w, "storage error", 500)
		return
	}
	writeJSON(w, 201, InitResponse{id})
}
func (s *Server) uploadAction(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, "/v1/uploads/")
	parts := strings.Split(suffix, "/")
	if len(parts) < 1 || len(parts) > 3 || len(parts[0]) != 32 || !isHex(parts[0]) {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	if len(parts) == 3 && parts[1] == "chunks" && r.Method == http.MethodPut {
		index, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || index < 0 {
			http.Error(w, "invalid chunk index", 400)
			return
		}
		s.putChunk(w, r, id, index)
		return
	}
	if _,err:=s.loadUpload(id);err!=nil{http.NotFound(w,r);return}
	mu := s.uploadMutex(id)
	mu.Lock()
	defer mu.Unlock()
	u, err := s.loadUpload(id)
	if err != nil {
		s.uploadLocks.Delete(id)
		http.NotFound(w, r)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, 200, u)
		return
	}
	if len(parts) == 2 && parts[1] == "complete" && r.Method == http.MethodPost {
		s.complete(w, r, u)
		return
	}
	http.Error(w, "method not allowed", 405)
}
func isHex(s string) bool { _, e := hex.DecodeString(s); return e == nil }
func (s *Server) putChunk(w http.ResponseWriter, r *http.Request, id string, index int64) {
	u, err := s.loadUpload(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if u.ChunkSize == 0 || index > (u.Size/u.ChunkSize) {
		http.Error(w, "chunk outside file", 400)
		return
	}
	offset := index * u.ChunkSize
	if offset >= u.Size {
		http.Error(w, "chunk outside file", 400)
		return
	}
	expected := u.ChunkSize
	if remaining := u.Size - offset; remaining < expected {
		expected = remaining
	}
	if r.ContentLength > expected {
		http.Error(w, "chunk too large", 413)
		return
	}
	// Spool the bounded request to a private temporary file rather than
	// allocating up to 64 MiB for every simultaneous upload request.
	staging, err := os.CreateTemp(filepath.Join(s.root, ".xer-data"), ".xer-chunk-*")
	if err != nil {
		r.Body.Close()
		http.Error(w, "storage error", 500)
		return
	}
	defer os.Remove(staging.Name())
	defer staging.Close()
	if err = staging.Chmod(0600); err != nil {
		r.Body.Close()
		http.Error(w, "storage error", 500)
		return
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(staging, h), io.LimitReader(r.Body, expected+1))
	r.Body.Close()
	if err != nil || n != expected {
		http.Error(w, "wrong chunk length", 400)
		return
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if !goodHash(r.Header.Get("X-Chunk-SHA256")) || digest != strings.ToLower(r.Header.Get("X-Chunk-SHA256")) {
		http.Error(w, "chunk hash mismatch", 422)
		return
	}
	// Buffer and authenticate the chunk before taking the state lock; chunks
	// may arrive concurrently but storage metadata updates are serialized.
	mu := s.uploadMutex(id)
	mu.Lock()
	defer mu.Unlock()
	u, err = s.loadUpload(id)
	if err != nil {
		s.uploadLocks.Delete(id)
		http.NotFound(w, r)
		return
	}
	if old, exists := u.Received[index]; exists {
		if old == digest {
			w.WriteHeader(204)
		} else {
			http.Error(w, "chunk conflict", 409)
		}
		return
	}
	f, err := openPrivate(s.partPath(u.ID), os.O_WRONLY)
	if err != nil {
		http.Error(w, "storage error", 500)
		return
	}
	if _, err = staging.Seek(0, io.SeekStart); err == nil {
		// SectionWriter confines the write to this chunk's expected range.
		_, err = io.CopyN(io.NewOffsetWriter(f, offset), staging, expected)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		http.Error(w, "storage write error", 500)
		return
	}
	u.Received[index] = digest
	if err := storeJSON(s.statePath(u.ID), u); err != nil {
		http.Error(w, "state update error", 500)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) complete(w http.ResponseWriter, r *http.Request, u Upload) {
	count := chunkCount(u.Size,u.ChunkSize)
	if int64(len(u.Received)) != count {
		http.Error(w, "missing chunks", 409)
		return
	}
	st, err := os.Stat(s.partPath(u.ID))
	if err != nil || st.Size() != u.Size {
		http.Error(w, "wrong file size", 409)
		return
	}
	digest, err := shaFileContext(r.Context(),s.partPath(u.ID))
	if err != nil || digest != u.SHA256 {
		http.Error(w, "full file hash mismatch", 422)
		return
	}
	dst := filepath.Join(s.root, u.Name)
	if err := os.Link(s.partPath(u.ID), dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			http.Error(w, "file already exists", 409)
		} else {
			http.Error(w, "commit failed", 500)
		}
		return
	}
	if err := os.Remove(s.partPath(u.ID)); err != nil { http.Error(w,"published but partial cleanup failed",500); return }
	if err := os.Remove(s.statePath(u.ID)); err != nil { http.Error(w,"published but metadata cleanup failed",500); return }
	if err := syncDirectory(s.root); err != nil { http.Error(w,"published but directory sync failed",500); return }
	s.uploadLocks.Delete(u.ID)
	writeJSON(w, 200, map[string]string{"sha256": digest, "file": u.Name})
}
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", 405)
		return
	}
	name, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/v1/files/"))
	if err != nil || !validName(name) {
		http.Error(w, "invalid file name", 400)
		return
	}
	path := filepath.Join(s.root, name)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	f, err := openDownloadSource(s.root, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil { http.Error(w,"file stat error",500); return }
	digest,err:=s.fileDigest(name,f)
	if err!=nil {http.Error(w,"file read/hash error",500);return}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "file seek error", 500)
		return
	}
	w.Header().Set("X-File-SHA256", digest)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, st.ModTime(), f)
}
func clientFor(p Profile, token string) (*http.Client, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) < 1 {
			return errors.New("missing peer certificate")
		}
		certificate := cs.PeerCertificates[0]
		now := time.Now()
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return errors.New("TLS receiver certificate is expired or not yet valid")
		}
		hash := sha256.Sum256(certificate.Raw)
		if hex.EncodeToString(hash[:]) != p.Fingerprint {
			return errors.New("TLS fingerprint mismatch: connection refused")
		}
		return nil
	}}, Proxy: http.ProxyFromEnvironment, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 45 * time.Second, TLSHandshakeTimeout: 15 * time.Second}
	if err := configureHTTPTransport(transport); err != nil {
		return nil, err
	}
	if token == "" {
		if err := clientIdentityTLS(transport.TLSClientConfig); err != nil {
			return nil, err
		}
	}
	return &http.Client{Transport: transport, Timeout: 0, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("redirect forbidden for XER file transfer")
	}}, nil
}
func request(client *http.Client, token, method, urlStr string, body io.Reader) (*http.Response, error) {
	if client == nil { return nil, errors.New("HTTPS client was not initialized") }
	req, err := http.NewRequestWithContext(context.Background(), method, urlStr, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerToken, "Bearer "+token)
	return client.Do(req)
}
func checkStatus(resp *http.Response, code int) error {
	if resp.StatusCode == code {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("remote HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
}
func clientStateDir() (string, error) {
	d, e := userCacheDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "xer", "uploads"), nil
}
func sendFile(path, alias string) error { return sendFileWithOptions(path, alias, chunkSize, 1) }
func sendFileWithOptions(path, alias string, selectedChunk int64, parallel int) error {
	if selectedChunk<1 || selectedChunk>maxChunk {return errors.New("chunk must be 1B..64MiB")}
	if parallel < 1 || parallel > 8 {
		return errors.New("parallel must be between 1 and 8")
	}
	p, err := getOrPair(alias)
	if err != nil {
		return err
	}
	token, tokenErr := optionalToken()
	if tokenErr != nil { return tokenErr }
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("source must be a regular file")
	}
	name := filepath.Base(path)
	if !validName(name) {
		return errors.New("unsupported filename")
	}
	digest, err := shaFile(path)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	stateKey := sha256.Sum256([]byte(p.Address + "|" + p.Fingerprint + "|" + abs + "|" + strconv.FormatInt(info.Size(), 10) + "|" + strconv.FormatInt(info.ModTime().UnixNano(), 10) + "|" + digest + "|" + strconv.FormatInt(selectedChunk, 10)))
	stateDir, err := clientStateDir()
	if err != nil {
		return err
	}
	statePath := filepath.Join(stateDir, hex.EncodeToString(stateKey[:])+".json")
	sendLock,err:=acquireLock(statePath+".lock");if err!=nil{return err};defer sendLock.Close()
	client, err := clientFor(p, token)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	base := "https://" + p.Address
	id := ""
	var state InitResponse
	if b, e := readPrivate(statePath,65536); e == nil && json.Unmarshal(b, &state) == nil && len(state.ID) == 32 && isHex(state.ID) {
		id = state.ID
		resp, e := request(client, token, "GET", base+"/v1/uploads/"+id, nil)
		if e != nil {
			return e
		}
		status:=resp.StatusCode
		resp.Body.Close()
		if status==404 {
			completed,e:=request(client,token,"HEAD",base+"/v1/files/"+url.PathEscape(name),nil)
			if e!=nil{return e}
			matched:=completed.StatusCode==200 && completed.Header.Get("X-File-SHA256")==digest && completed.ContentLength==info.Size()
			completed.Body.Close()
			if matched {if e=os.Remove(statePath);e!=nil{return e};fmt.Println("Upload already committed; verified receiver digest.");return nil}
			id=""
		} else if status!=200 {return fmt.Errorf("resume status HTTP %d",status)}
	}
	if id == "" {
		requestBody, _ := json.Marshal(InitRequest{Name: name, Size: info.Size(), ChunkSize: selectedChunk, SHA256: digest})
		resp, e := request(client, token, "POST", base+"/v1/uploads", bytes.NewReader(requestBody))
		if e != nil {
			return e
		}
		defer resp.Body.Close()
		if err := checkStatus(resp, 201); err != nil {
			return err
		}
		if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
			return err
		}
		id = state.ID
		if len(id) != 32 || !isHex(id) {
			return errors.New("receiver returned invalid upload ID")
		}
		if err := storeJSON(statePath, state); err != nil {
			return err
		}
	}
	resp, err := request(client, token, "GET", base+"/v1/uploads/"+id, nil)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 200); err != nil {
		resp.Body.Close()
		return err
	}
	var remote Upload
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&remote); err != nil {
		resp.Body.Close()
		return err
	}
	resp.Body.Close()
	if remote.Name != name || remote.Size != info.Size() || remote.SHA256 != digest || remote.ChunkSize != selectedChunk {
		return errors.New("remote resume metadata mismatch")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	chunks := chunkCount(info.Size(),selectedChunk)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan int64)
	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once
	var progress int64
	var progressMu sync.Mutex
	worker := func() {
		defer wg.Done()
		for i := range queue {
			if ctx.Err() != nil {
				return
			}
			offset := i * selectedChunk
			length := selectedChunk
			if info.Size()-offset < length {
				length = info.Size() - offset
			}
			// Hash and send using bounded streaming readers. No per-worker
			// 64 MiB allocation is necessary for large chunks.
			h := sha256.New()
			if _, e := io.Copy(h, io.NewSectionReader(f, offset, length)); e != nil {
				once.Do(func() { firstErr = e; cancel() })
				return
			}
			digestBytes := h.Sum(nil)
			chunkURL := fmt.Sprintf("%s/v1/uploads/%s/chunks/%d", base, id, i)
			var e error
			for attempt := 0; attempt < 3; attempt++ {
				if ctx.Err() != nil {
					return
				}
				var req *http.Request
				req, e = http.NewRequestWithContext(ctx, "PUT", chunkURL, io.NewSectionReader(f, offset, length))
				if e != nil {
					break
				}
				req.Header.Set(headerToken, "Bearer "+token)
				req.Header.Set("X-Chunk-SHA256", hex.EncodeToString(digestBytes))
				var response *http.Response
				response, e = client.Do(req)
				if e == nil {
					e = checkStatus(response, 204)
					response.Body.Close()
				}
				if e == nil {
					break
				}
				if attempt < 2 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(attempt+1) * time.Second):
					}
				}
			}
			if e != nil {
				once.Do(func() { firstErr = fmt.Errorf("chunk %d: %w", i, e); cancel() })
				return
			}
			progressMu.Lock()
			progress++
			fmt.Printf("\rUploaded %d / %d chunks", progress, chunks)
			progressMu.Unlock()
		}
	}
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go worker()
	}
feed:
	for i := int64(0); i < chunks; i++ {
		if _, ok := remote.Received[i]; ok {
			continue
		}
		select {
		case <-ctx.Done():
			break feed
		case queue <- i:
		}
	}
	close(queue)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	fmt.Println()
	if err=completeUpload(client,token,base+"/v1/uploads/"+id+"/complete");err!=nil{return err}
	if err := os.Remove(statePath); err != nil && !errors.Is(err,os.ErrNotExist) { return fmt.Errorf("upload complete; cache cleanup: %w",err) }
	fmt.Printf("Upload complete: %s\n", name)
	return nil
}
func doctor() error {
	fmt.Printf("XER %s | OS=%s ARCH=%s\n", version, runtime.GOOS, runtime.GOARCH)
	p, err := loadProfiles()
	if err != nil {
		return err
	}
	fmt.Printf("Configured servers: %d\n", len(p.Servers))
	if _, err := tokenValue(); err != nil {
		fmt.Println("Access token: not configured")
	} else {
		fmt.Println("Access token: available")
	}
	fmt.Println("Transport: native HTTPS/TLS 1.3 with pinned receiver certificate")
	fmt.Printf("Chunk upload: %d bytes, %d worker(s), per-chunk + full SHA-256\n",activeSettings.Chunk,activeSettings.Parallel)
	return nil
}


