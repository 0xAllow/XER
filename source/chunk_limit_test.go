package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestChunkLimit64MiB(t *testing.T) {
	for _, v := range []string{"1M", "8M", "16M", "32M", "64M"} {
		if _, err := parseChunk(v); err != nil {
			t.Fatalf("%s must be valid: %v", v, err)
		}
	}
	for _, v := range []string{"0", "65M", "-1M", "9999999999M"} {
		if _, err := parseChunk(v); err == nil {
			t.Fatalf("%s must be rejected", v)
		}
	}
}

func TestLargeChunkStreamingRoundTrip(t *testing.T) {
	root, _, _, _ := testReceiver(t)
	data := bytes.Repeat([]byte("XER streaming large chunk: 0123456789abcdef"), 490000)
	path := filepath.Join(t.TempDir(), "large-chunk.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := sendFileWithOptions(path, "local", 16*1024*1024, 2); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "large-chunk.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("received file mismatch: %v", err)
	}
}
