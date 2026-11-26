package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignedRelease(t *testing.T) {
	d := t.TempDir()
	artifact := filepath.Join(d, "xer.exe")
	if err := os.WriteFile(artifact, []byte("sample release"), 0644); err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	priv, pub := filepath.Join(keys, "key.pem"), filepath.Join(keys, "key.pub")
	if err := run([]string{"keygen", "--private", priv, "--public", pub}); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(d, "SHA256SUMS")
	if err := writeManifest(d, manifest); err != nil {
		t.Fatal(err)
	}
	sig := filepath.Join(d, "SHA256SUMS.sig")
	if err := run([]string{"sign", "--manifest", manifest, "--private", priv, "--signature", sig}); err != nil {
		t.Fatal(err)
	}
	verify := []string{"verify", "--manifest", manifest, "--public", pub, "--signature", sig, "--dir", d}
	if err := run(verify); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := run(verify); err == nil {
		t.Fatal("expected tamper detection")
	}
}
func TestManifestTraversal(t *testing.T) {
	if err := verifyManifest(t.TempDir(), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ../escape\n")); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestManifestRefusesSigningPrivateKey(t *testing.T){
 dir:=t.TempDir();priv,pub:=filepath.Join(dir,"key.pem"),filepath.Join(dir,"key.pub")
 if err:=run([]string{"keygen","--private",priv,"--public",pub});err!=nil{t.Fatal(err)}
 if err:=writeManifest(dir,filepath.Join(dir,"SHA256SUMS"));err==nil{t.Fatal("private signing key accepted in artifact directory")}
}
func TestKeygenNeverOverwrites(t *testing.T){
 dir:=t.TempDir();priv,pub:=filepath.Join(dir,"key.pem"),filepath.Join(dir,"key.pub")
 original:=[]byte("keep this file")
 if err:=os.WriteFile(priv,original,0600);err!=nil{t.Fatal(err)}
 if err:=run([]string{"keygen","--private",priv,"--public",pub});err==nil{t.Fatal("existing private path overwritten")}
 actual,err:=os.ReadFile(priv);if err!=nil || string(actual)!=string(original){t.Fatal("private file changed",err)}
}
