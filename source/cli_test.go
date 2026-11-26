package main

import (
	"strings"
	"testing"
)

func TestManualViaRequired(t *testing.T) {
	if _, _, _, _, e := transferArgs([]string{"file.txt", "host"}); e == nil {
		t.Fatal("accepted implicit protocol")
	}
}
func TestManualOptions(t *testing.T) {
	pos, via, chunk, parallel, e := transferArgs([]string{"file.txt", "host", "--via", "https", "--chunk", "4M", "--parallel", "1"})
	if e != nil || via != "https" || chunk != 4*1024*1024 || parallel != 1 || len(pos) != 2 {
		t.Fatalf("bad parse: %v %s %d %d %v", pos, via, chunk, parallel, e)
	}
	for _, a := range [][]string{
		{"--via", "ftp", "--junk", "1"}, {"--via", "https", "--chunk", "9999M"}, {"--via", "https", "--parallel", "0"},
	} {
		if _, _, _, _, e := transferArgs(a); e == nil {
			t.Fatalf("accepted unsafe options %v", a)
		}
	}
}
func TestPairCodeBindsBothIdentities(t *testing.T) {
	a := pairCode([]byte("receiver"), []byte("client"))
	if len(a) != 20 {
		t.Fatal("incorrect pairing display size")
	}
	if a == pairCode([]byte("other receiver"), []byte("client")) || a == pairCode([]byte("receiver"), []byte("other client")) {
		t.Fatal("pairing code not bound to both certificates")
	}
}
func TestAutomationNeedsExplicitProtocol(t *testing.T) {
	if _, e := parseJob([]byte("name: backup\nfrom: file\nto: vault\nevery: manual\n")); e == nil || !strings.Contains(e.Error(), "via") {
		t.Fatal("missing via accepted")
	}
}

func TestTransportSpecificFlagsAreNotSilentlyIgnored(t *testing.T){
 if _,reset,e:=extractNetworkArgs([]string{"--proxy",""});e==nil{reset();t.Fatal("empty explicit proxy selected direct networking")}
 if e:=dispatchSend([]string{"missing","127.0.0.1","--via","https","--port","2222"});e==nil || !strings.Contains(e.Error(),"HTTPS"){t.Fatal("HTTPS --port was silently ignored",e)}
 if e:=dispatchGet([]string{"admin@127.0.0.1:file","--via","sftp","--parallel","1"});e==nil || !strings.Contains(e.Error(),"chunk/parallel"){t.Fatal("unsupported default-valued option was silently ignored",e)}
}
