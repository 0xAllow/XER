// XER artifact manifest signing and verification utility.
// Author: 0xAllow. All cryptographic operations use the Go standard library.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xer-artifact:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xer-artifact keygen|manifest|sign|verify [options]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := fs.String("dir", ".", "artifact directory")
	manifest := fs.String("manifest", "SHA256SUMS", "checksum manifest")
	private := fs.String("private", "", "Ed25519 private key PEM (outside the repository)")
	public := fs.String("public", "", "trusted Ed25519 public key PEM")
	signature := fs.String("signature", "SHA256SUMS.sig", "detached signature path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		if *private == "" || *public == "" {
			return errors.New("keygen requires --private and --public")
		}
		if _, err := os.Stat(*private); err == nil {
			return errors.New("private key already exists; refusing overwrite")
		}
		if _, err := os.Stat(*public); err == nil {
			return errors.New("public key already exists; refusing overwrite")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		if err := writeNewKey(*private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
			return err
		}
		if err := writeNewKey(*public, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
			return err
		}
		fmt.Println("Created signing keys. Keep the private key offline and outside release archives.")
		return nil
	case "manifest":
		return writeManifest(*dir, *manifest)
	case "sign":
		if *private == "" {
			return errors.New("sign requires --private")
		}
		data, err := os.ReadFile(*manifest)
		if err != nil {
			return err
		}
		pk, err := readPrivate(*private)
		if err != nil {
			return err
		}
		return os.WriteFile(*signature, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(pk, data))+"\n"), 0644)
	case "verify":
		if *public == "" {
			return errors.New("verify requires --public (trusted out of band)")
		}
		data, err := os.ReadFile(*manifest)
		if err != nil {
			return err
		}
		pub, err := readPublic(*public)
		if err != nil {
			return err
		}
		signatureText, err := os.ReadFile(*signature)
		if err != nil {
			return err
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureText)))
		if err != nil {
			return err
		}
		if !ed25519.Verify(pub, data, sig) {
			return errors.New("INVALID SIGNATURE: manifest not authenticated")
		}
		if err := verifyManifest(*dir, data); err != nil {
			return err
		}
		fmt.Println("OK: trusted Ed25519 signature and all artifact SHA-256 digests verified")
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func readPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("expected Ed25519 private key")
	}
	return pk, nil
}
func readPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public PEM")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("expected Ed25519 public key")
	}
	return pk, nil
}
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func safeFile(dir, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.Base(name) != name || strings.ContainsAny(name, "\\/\r\n") || name == "." || name == ".." {
		return "", fmt.Errorf("unsafe manifest filename %q", name)
	}
	path := filepath.Join(dir, name)
	stat, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", name)
	}
	return path, nil
}
func writeManifest(dir, path string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	names := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if name == filepath.Base(path) || name == "SHA256SUMS.sig" || !entry.Type().IsRegular() {
			continue
		}
		if err:=rejectPrivateMaterial(filepath.Join(dir,name));err!=nil{return err}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return errors.New("no regular artifacts to hash")
	}
	var out strings.Builder
	for _, name := range names {
		p, err := safeFile(dir, name)
		if err != nil {
			return err
		}
		h, err := fileHash(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(&out, "%s  %s\n", h, name)
	}
	return os.WriteFile(path, []byte(out.String()), 0644)
}
func verifyManifest(dir string, data []byte) error {
	seen := map[string]bool{}
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return errors.New("invalid checksum manifest line")
		}
		digest := line[:64]
		if _, err := hex.DecodeString(digest); err != nil {
			return err
		}
		name := line[66:]
		if seen[name] {
			return fmt.Errorf("duplicate manifest file %q", name)
		}
		seen[name] = true
		path, err := safeFile(dir, name)
		if err != nil {
			return err
		}
		actual, err := fileHash(path)
		if err != nil {
			return err
		}
		if actual != strings.ToLower(digest) {
			return fmt.Errorf("CHECKSUM MISMATCH: %s", name)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("empty checksum manifest")
	}
	return nil
}

func writeNewKey(path string,data []byte,mode os.FileMode) error {
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,mode);if err!=nil{return err};defer f.Close()
 if mode==0600{if err=secureKeyFile(path);err!=nil{return err}}
 if _,err=f.Write(data);err!=nil{return err};if err=f.Sync();err!=nil{return err};return f.Close()
}
func rejectPrivateMaterial(path string)error{
 f,err:=os.Open(path);if err!=nil{return err};defer f.Close()
 b,err:=io.ReadAll(io.LimitReader(f,8192));if err!=nil{return err}
 if strings.HasSuffix(strings.ToLower(path),".key") || strings.Contains(string(b),"-----BEGIN PRIVATE KEY-----") || strings.Contains(string(b),"-----BEGIN EC PRIVATE KEY-----") || strings.Contains(string(b),"-----BEGIN RSA PRIVATE KEY-----") || strings.Contains(string(b),"-----BEGIN OPENSSH PRIVATE KEY-----"){return errors.New("private signing material must not be in the artifact directory")}
 return nil
}
