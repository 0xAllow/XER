package main
import("os";"os/exec";"path/filepath";"runtime";"strings";"testing")
// This tests the exact batch escaping against a real local OpenSSH subsystem,
// through pipes. It does not claim SSH host-key/authentication interoperability.
func TestLocalOpenSSHBatchRoundTrip(t *testing.T){
 if runtime.GOOS=="windows"{t.Skip("local sftp-server path is Unix-specific")}
 sftp,e:=exec.LookPath("sftp");if e!=nil{t.Skip("OpenSSH sftp unavailable")}
 server:="";for _,candidate:=range []string{"/usr/lib/openssh/sftp-server","/usr/lib/ssh/sftp-server","/usr/libexec/sftp-server"}{if _,e=os.Stat(candidate);e==nil{server=candidate;break}}
 if server==""{t.Skip("local OpenSSH sftp-server unavailable")}
 dir:=t.TempDir();source:=filepath.Join(dir,`literal[1] and "quote".bin`);remote:=filepath.Join(dir,"remote.bin");dest:=filepath.Join(dir,"download.bin")
 data:=[]byte("local sftp component test\n");if e=os.WriteFile(source,data,0600);e!=nil{t.Fatal(e)}
 a,e:=sftpQuote(source);if e!=nil{t.Fatal(e)};b,e:=sftpQuote(remote);if e!=nil{t.Fatal(e)};c,e:=sftpQuote(dest);if e!=nil{t.Fatal(e)}
 cmd:=exec.Command(sftp,"-D",server,"-b","-");cmd.Stdin=strings.NewReader("put "+a+" "+b+"\nget "+b+" "+c+"\n")
 if output,e:=cmd.CombinedOutput();e!=nil{t.Fatalf("local sftp: %v: %s",e,output)}
 got,e:=os.ReadFile(dest);if e!=nil || string(got)!=string(data){t.Fatal("local SFTP round trip differs",e)}
}
