package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func isolateUserState(t *testing.T) {
 t.Helper();cfg,cache:=t.TempDir(),t.TempDir();oldCfg,oldCache:=userConfigDir,userCacheDir
 userConfigDir=func()(string,error){return cfg,nil};userCacheDir=func()(string,error){return cache,nil}
 t.Cleanup(func(){userConfigDir=oldCfg;userCacheDir=oldCache})
}

func testReceiver(t *testing.T) (string, Profile, string, *http.Client) {
	t.Helper()
	isolateUserState(t)
	root := t.TempDir()
	token := "test-secret-from-test"
	srv := &Server{root: root, token: token}
	if err := os.MkdirAll(filepath.Join(root, ".xer-data"), 0700); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/uploads", srv.auth(srv.uploadInit))
	mux.HandleFunc("/v1/uploads/", srv.auth(srv.uploadAction))
	mux.HandleFunc("/v1/files/", srv.auth(srv.download))
	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	raw := ts.TLS.Certificates[0].Certificate[0]
	digest := sha256.Sum256(raw)
	p := Profile{Address: strings.TrimPrefix(ts.URL, "https://"), Fingerprint: hex.EncodeToString(digest[:])}
	t.Setenv("XER_TOKEN", token)
	profiles := Profiles{Servers: map[string]Profile{"local": p}}
	config, err := configFile()
	if err != nil {
		t.Fatal(err)
	}
	if err := storeJSON(config, profiles); err != nil {
		t.Fatal(err)
	}
	client, err := clientFor(p, token)
	if err != nil {
		t.Fatal(err)
	}
	return root, p, token, client
}
func TestSecureChunkedUploadDownload(t *testing.T) {
	root, _, _, _ := testReceiver(t)
	data := bytes.Repeat([]byte("XER is encrypted, chunked and verified.\n"), 90000)
	source := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := sendFile(source, "local"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "sample.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("upload differs from source")
	}
	dest := filepath.Join(t.TempDir(), "received.bin")
	if err := getFile("local:sample.bin", dest); err != nil {
		t.Fatal(err)
	}
	downloaded, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded, data) {
		t.Fatal("download differs from source")
	}
	if err := getFile("local:sample.bin", dest); err == nil {
		t.Fatal("existing destination must not be overwritten")
	}
	if err := sendFile(source, "local"); err == nil {
		t.Fatal("existing uploaded destination must not be overwritten")
	}
}
func TestResumeUpload(t *testing.T) {
	root, p, token, client := testReceiver(t)
	data := bytes.Repeat([]byte("Chunked resumable contents"), 100000)
	source := filepath.Join(t.TempDir(), "resume.bin")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest, _ := shaFile(source)
	body, _ := json.Marshal(InitRequest{Name: "resume.bin", Size: int64(len(data)), ChunkSize: chunkSize, SHA256: digest})
	resp, err := request(client, token, "POST", "https://"+p.Address+"/v1/uploads", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatal(resp.Status)
	}
	var state InitResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	first := data[:chunkSize]
	h := sha256.Sum256(first)
	req, _ := http.NewRequest("PUT", "https://"+p.Address+"/v1/uploads/"+state.ID+"/chunks/0", bytes.NewReader(first))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Chunk-SHA256", hex.EncodeToString(h[:]))
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 204 {
		t.Fatal(r.Status)
	}
	info, _ := os.Stat(source)
	abs, _ := filepath.Abs(source)
	key := sha256.Sum256([]byte(p.Address + "|" + p.Fingerprint + "|" + abs + "|" + strconv.FormatInt(info.Size(), 10) + "|" + strconv.FormatInt(info.ModTime().UnixNano(), 10) + "|" + digest + "|" + strconv.FormatInt(chunkSize, 10)))
	sd, _ := clientStateDir()
	if err := storeJSON(filepath.Join(sd, hex.EncodeToString(key[:])+".json"), state); err != nil {
		t.Fatal(err)
	}
	if err := sendFile(source, "local"); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(filepath.Join(root, "resume.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, data) {
		t.Fatal("resumed file differs")
	}
}
func TestAuthAndPinning(t *testing.T) {
	_, p, token, client := testReceiver(t)
	r, err := request(client, "wrong-token", "HEAD", "https://"+p.Address+"/v1/files/anything", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", r.StatusCode)
	}
	p.Fingerprint = strings.Repeat("0", 64)
	wrong, err := clientFor(p, token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = request(wrong, token, "HEAD", "https://"+p.Address+"/v1/files/anything", nil)
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected TLS pin failure, got %v", err)
	}
}
func TestRejectBadChunkAndTraversal(t *testing.T) {
	_, p, token, client := testReceiver(t)
	for _, name := range []string{"../bad", "a/b", "a\\b", ".xer-secret", "file:name"} {
		if validName(name) {
			t.Fatalf("accepted unsafe name %q", name)
		}
	}
	payload, _ := json.Marshal(InitRequest{Name: "good.txt", Size: 5, ChunkSize: chunkSize, SHA256: strings.Repeat("a", 64)})
	resp, err := request(client, token, "POST", "https://"+p.Address+"/v1/uploads", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	var state InitResponse
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	req, _ := http.NewRequest("PUT", "https://"+p.Address+"/v1/uploads/"+state.ID+"/chunks/0", strings.NewReader("HELLO"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Chunk-SHA256", strings.Repeat("0", 64))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 422 {
		t.Fatalf("bad hash accepted: %d", resp.StatusCode)
	}
}
func TestEmptyFile(t *testing.T) {
	root, _, _, _ := testReceiver(t)
	source := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(source, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := sendFile(source, "local"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "empty.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatal("nonempty destination")
	}
}

func TestResumableDownload(t *testing.T) {
	root, _, _, _ := testReceiver(t)
	data := bytes.Repeat([]byte("download resume test"), 120000)
	if err := os.WriteFile(filepath.Join(root, "download.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "final.bin")
	if err := os.WriteFile(dest+".xer-part", data[:10000], 0600); err != nil {
		t.Fatal(err)
	}
	if err := getFile("local:download.bin", dest); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, data) {
		t.Fatal("download resume data mismatch")
	}
}
