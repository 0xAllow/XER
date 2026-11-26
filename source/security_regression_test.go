package main

import (
 "bytes"
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "math/big"
 "net"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync/atomic"
 "testing"
 "time"
)

func auditIdentity(t *testing.T,expired bool)tls.Certificate{
 t.Helper();key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 before,after:=time.Now().Add(-time.Hour),time.Now().Add(time.Hour)
 if expired{before=time.Now().Add(-2*time.Hour);after=time.Now().Add(-time.Hour)}
 template:=x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"local audit client"},NotBefore:before,NotAfter:after,KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
 der,e:=x509.CreateCertificate(rand.Reader,&template,&template,&key.PublicKey,key);if e!=nil{t.Fatal(e)}
 return tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
}
func auditNativeServer(t *testing.T,root string,pairing bool)(*Server,*httptest.Server,Profile){
 t.Helper();cert,pin,e:=makeCert(filepath.Join(root,".xer-data"));if e!=nil{t.Fatal(e)}
 srv:=&Server{root:root,certDER:cert.Certificate[0]};if pairing{srv.pairingUntil=time.Now().Add(time.Minute)}
 mux:=http.NewServeMux();mux.HandleFunc("/v1/pair",srv.pair);mux.HandleFunc("/v1/pair/",srv.pairAction)
 mux.HandleFunc("/v1/uploads",srv.auth(srv.uploadInit));mux.HandleFunc("/v1/uploads/",srv.auth(srv.uploadAction));mux.HandleFunc("/v1/files/",srv.auth(srv.download))
 ts:=httptest.NewUnstartedServer(srv.limitResponse(mux));ts.TLS=&tls.Config{MinVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{cert},ClientAuth:tls.RequestClientCert};ts.StartTLS();t.Cleanup(ts.Close)
 return srv,ts,Profile{Address:strings.TrimPrefix(ts.URL,"https://"),Fingerprint:pin}
}
func auditClient(t *testing.T,p Profile,id tls.Certificate)*http.Client{
 t.Helper();tr:=&http.Transport{TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS13,InsecureSkipVerify:true,GetClientCertificate:func(*tls.CertificateRequestInfo)(*tls.Certificate,error){return &id,nil},VerifyConnection:func(cs tls.ConnectionState)error{if len(cs.PeerCertificates)!=1 || fingerprint(cs.PeerCertificates[0].Raw)!=p.Fingerprint{return fmt.Errorf("test pin mismatch")};return certValid(cs.PeerCertificates[0])}}}
 t.Cleanup(tr.CloseIdleConnections);return &http.Client{Transport:tr,Timeout:5*time.Second}
}
func auditStatus(t *testing.T,client *http.Client,method,endpoint string,body io.Reader,expected int)*http.Response{
 t.Helper();req,e:=http.NewRequest(method,endpoint,body);if e!=nil{t.Fatal(e)};r,e:=client.Do(req);if e!=nil{t.Fatal(e)}
 if r.StatusCode!=expected{data,_:=io.ReadAll(io.LimitReader(r.Body,4096));r.Body.Close();t.Fatalf("%s: status %d, want %d: %s",endpoint,r.StatusCode,expected,data)};return r
}
func TestPairingBothApprovalsAndNativeTransfer(t *testing.T){
 isolateUserState(t)
 t.Setenv("XDG_CONFIG_HOME",t.TempDir());t.Setenv("XDG_CACHE_HOME",t.TempDir());t.Setenv("XER_TOKEN","");t.Setenv("XER_TOKEN_FILE","")
 oldNet:=activeNetwork;activeNetwork=networkOptions{};defer func(){activeNetwork=oldNet}()
 root:=t.TempDir();_,ts,p:=auditNativeServer(t,root,true);t.Chdir(root)
 input,writer,e:=os.Pipe();if e!=nil{t.Fatal(e)};oldInput:=os.Stdin;os.Stdin=input
 defer func(){os.Stdin=oldInput;input.Close();writer.Close()}()
 done:=make(chan error,1);go func(){_,err:=pairAddress(p.Address);done<-err}()
 var pending pairSession;deadline:=time.Now().Add(3*time.Second)
 for {e=readPrivateJSON(pairPath(root),&pending,65536);if e==nil{break};if time.Now().After(deadline){writer.Close();t.Fatal("receiver did not receive a challenge before sender input")};time.Sleep(10*time.Millisecond)}
 trusted,e:=readTrusted(root);if e!=nil || len(trusted)!=0{t.Fatal("challenge alone must not authorize",e)}
 if e=trustCommand([]string{"approve",pending.ID,"WRONG"});e==nil{t.Fatal("wrong code accepted")}
 if e=trustCommand([]string{"approve",pending.ID,pending.Code});e!=nil{t.Fatal(e)}
 trusted,e=readTrusted(root);if e!=nil || len(trusted)!=0{t.Fatal("receiver approval alone must not authorize",e)}
 writer.Write([]byte("YES\n"))
 select{case e=<-done:if e!=nil{t.Fatal(e)};case <-time.After(5*time.Second):t.Fatal("pairing did not finish")}
 profiles,e:=loadProfiles();if e!=nil || profiles.Servers[p.Address].Fingerprint!=p.Fingerprint{t.Fatal("receiver profile not persisted",e)}
 original:=bytes.Repeat([]byte("native paired transfer\n"),10000);source:=filepath.Join(t.TempDir(),"native.bin")
 if e=os.WriteFile(source,original,0600);e!=nil{t.Fatal(e)}
 if e=sendFileWithOptions(source,p.Address,65536,4);e!=nil{t.Fatal(e)}
 dest:=filepath.Join(t.TempDir(),"out.bin");if e=getFile(p.Address+":native.bin",dest);e!=nil{t.Fatal(e)}
 received,e:=os.ReadFile(dest);if e!=nil || sha256.Sum256(received)!=sha256.Sum256(original){t.Fatal("native transfer integrity mismatch",e)}
 // Recreate the receiver around the same on-disk identity and trust database.
 ts.Close();_,_,next:=auditNativeServer(t,root,false)
 if next.Fingerprint!=p.Fingerprint{t.Fatal("receiver identity changed on restart")}
 if e=updateProfiles(func(all *Profiles)error{all.Servers["restart"]=next;return nil});e!=nil{t.Fatal(e)}
 if e=getFile("restart:native.bin",filepath.Join(t.TempDir(),"after-restart.bin"));e!=nil{t.Fatal("trust not retained across receiver restart",e)}
}
func TestExpiryRevocationAndTLS13(t *testing.T){
 root:=t.TempDir();_,_,p:=auditNativeServer(t,root,false)
 valid,expired:=auditIdentity(t,false),auditIdentity(t,true)
 if e:=os.WriteFile(filepath.Join(root,"test.bin"),[]byte("test"),0600);e!=nil{t.Fatal(e)}
 if e:=storeJSON(trustedPath(root),map[string]bool{fingerprint(valid.Certificate[0]):true,fingerprint(expired.Certificate[0]):true});e!=nil{t.Fatal(e)}
 client:=auditClient(t,p,valid);endpoint:="https://"+p.Address+"/v1/files/test.bin"
 r:=auditStatus(t,client,"HEAD",endpoint,nil,200);r.Body.Close()
 r=auditStatus(t,auditClient(t,p,expired),"HEAD",endpoint,nil,401);r.Body.Close()
 // Atomic revocation affects new requests, including a reused TLS connection.
 t.Chdir(root);if e:=trustCommand([]string{"remove",fingerprint(valid.Certificate[0])});e!=nil{t.Fatal(e)}
 r=auditStatus(t,client,"HEAD",endpoint,nil,401);r.Body.Close()
 oldTLS:=&http.Client{Transport:&http.Transport{TLSClientConfig:&tls.Config{MaxVersion:tls.VersionTLS12,InsecureSkipVerify:true}},Timeout:time.Second}
 defer oldTLS.CloseIdleConnections();if r,e:=oldTLS.Get(endpoint);e==nil{r.Body.Close();t.Fatal("TLS 1.2 was accepted")}
}
func TestPendingPairingBoundedExpiredAndCanceled(t *testing.T){
 root:=t.TempDir();srv,_,p:=auditNativeServer(t,root,true);id:=auditIdentity(t,false);client:=auditClient(t,p,id)
 hello:=func(nonce string)*http.Response{return auditStatus(t,client,"POST","https://"+p.Address+"/v1/pair",strings.NewReader(`{"nonce":"`+nonce+`"}`),202)}
 r:=hello(strings.Repeat("a",64));var pending pairSession;if e:=json.NewDecoder(r.Body).Decode(&pending);e!=nil{t.Fatal(e)};r.Body.Close()
 r=auditStatus(t,client,"POST","https://"+p.Address+"/v1/pair",strings.NewReader(`{"nonce":"`+strings.Repeat("b",64)+`"}`),409);r.Body.Close()
 r=auditStatus(t,client,"DELETE","https://"+p.Address+"/v1/pair/"+pending.ID,nil,204);r.Body.Close()
 r=hello(strings.Repeat("c",64));json.NewDecoder(r.Body).Decode(&pending);r.Body.Close()
 pending.Expires=time.Now().Add(-time.Second);if e:=storeJSON(pairPath(root),pending);e!=nil{t.Fatal(e)}
 r=auditStatus(t,client,"POST","https://"+p.Address+"/v1/pair/"+pending.ID,nil,410);r.Body.Close()
 trusted,e:=readTrusted(srv.root);if e!=nil || len(trusted)>0{t.Fatal("canceled/expired pairing authorized a device",e)}
}
func TestDownloadPartialLinksAndPrivateResume(t *testing.T){
 for _,kind:=range []string{"symlink","hardlink"}{t.Run(kind,func(t *testing.T){
  root,_,_,_:=testReceiver(t);data:=bytes.Repeat([]byte("safe download\n"),1000)
  if e:=os.WriteFile(filepath.Join(root,"remote.bin"),data,0600);e!=nil{t.Fatal(e)}
  dir:=t.TempDir();victim:=filepath.Join(dir,"unrelated.bin");dest:=filepath.Join(dir,"out.bin");os.WriteFile(victim,nil,0600)
  var e error;if kind=="symlink"{e=os.Symlink(victim,dest+".xer-part")}else{e=os.Link(victim,dest+".xer-part")};if e!=nil{t.Skip(e)}
  if e=getFile("local:remote.bin",dest);e!=nil{t.Fatal(e)}
  got,e:=os.ReadFile(victim);if e!=nil || len(got)!=0{t.Fatal("legacy partial link modified an unrelated file",e)}
  got,e=os.ReadFile(dest);if e!=nil || !bytes.Equal(got,data){t.Fatal("download mismatch",e)}
 })}
 root,p,_,_:=testReceiver(t);data:=bytes.Repeat([]byte("private resume\n"),1000);os.WriteFile(filepath.Join(root,"resume.bin"),data,0600)
 dest:=filepath.Join(t.TempDir(),"resumed.bin");h:=sha256.Sum256(data);meta:=downloadMetadata{p.Address,p.Fingerprint,"resume.bin",int64(len(data)),hex.EncodeToString(h[:])}
 stage,e:=newDownloadStage(dest,meta);if e!=nil{t.Fatal(e)}
 f,e:=stage.root.OpenFile("part",os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if e!=nil{t.Fatal(e)};f.Write(data[:37]);f.Close();stage.Close()
 if e=getFile("local:resume.bin",dest);e!=nil{t.Fatal(e)}
 got,e:=os.ReadFile(dest);if e!=nil || !bytes.Equal(got,data){t.Fatal("private resume mismatch",e)}
}
func TestPrivateStagingRejectsLinksAndConcurrentWriter(t *testing.T){
 dest:=filepath.Join(t.TempDir(),"out.bin");meta:=downloadMetadata{Address:"local",Pin:"pin",Name:"name",Digest:strings.Repeat("a",64)}
 stage,e:=newDownloadStage(dest,meta);if e!=nil{t.Fatal(e)};defer stage.Close()
 if other,e:=newDownloadStage(dest,meta);e==nil{other.Close();t.Fatal("concurrent staging lock acquired")}
 victim:=filepath.Join(t.TempDir(),"victim");os.WriteFile(victim,nil,0600)
 if e=os.Symlink(victim,filepath.Join(stage.root.Name(),"part"));e==nil{
  f,e:=stage.root.OpenFile("part",os.O_RDWR|safeReadFlags(),0600);if e==nil{defer f.Close();if e=validateOpenFile(f,true);e==nil{t.Fatal("staging symlink accepted")}}
 }
}
func TestDownloadRootRejectsExternalSymlinkAndHardlink(t *testing.T){
 root:=t.TempDir();outside:=filepath.Join(t.TempDir(),"outside");os.WriteFile(outside,[]byte("outside"),0600)
 for _,kind:=range []string{"symlink","hardlink"}{name:=kind+".bin";var e error;if kind=="symlink"{e=os.Symlink(outside,filepath.Join(root,name))}else{e=os.Link(outside,filepath.Join(root,name))};if e!=nil{continue}
  if f,e:=openDownloadSource(root,name);e==nil{f.Close();t.Fatal("external link accepted",kind)}
 }
}
func TestClientInitializationErrorIsReturned(t *testing.T){
 isolateUserState(t)
 t.Setenv("XDG_CONFIG_HOME",t.TempDir());d,e:=configDir();if e!=nil{t.Fatal(e)};d=filepath.Join(d,"identity");if e=privateDir(d);e!=nil{t.Fatal(e)}
 if e=writeExclusive(filepath.Join(d,"receiver.key"),[]byte("disposable incomplete identity"));e!=nil{t.Fatal(e)}
 client,e:=clientFor(Profile{Address:"127.0.0.1:1",Fingerprint:strings.Repeat("a",64)},"")
 if e==nil || client!=nil{t.Fatal("identity initialization failure was not propagated")}
}
func TestChunkCountOverflowAndReceiverQuotas(t *testing.T){
 if chunkCount(int64(1<<63-1),64<<20)<=0{t.Fatal("chunk count overflow")}
 root:=t.TempDir();privateDir(filepath.Join(root,".xer-data"));srv:=&Server{root:root,limits:receiverLimits{MaxFile:8,MaxChunks:4,MaxPending:1,MaxStorage:16}}
 init:=func(name string,size,chunk int64,want int){t.Helper();body,_:=json.Marshal(InitRequest{name,size,chunk,strings.Repeat("a",64)});w:=httptest.NewRecorder();srv.uploadInit(w,httptest.NewRequest("POST","/v1/uploads",bytes.NewReader(body)));if w.Code!=want{t.Fatalf("init status %d, want %d: %s",w.Code,want,w.Body.String())}}
 init("large",9,4,400);init("chunks",8,1,400);init("first",4,1,201);init("second",4,1,507)
 for _,name:=range []string{"NUL","CON.txt","COM1.bin","LPT¹.txt"}{if validName(name){t.Fatal("Windows reserved name accepted",name)}}
}
func TestUploadResumeWithChangedChunkSize(t *testing.T){
 root,p,token,client:=testReceiver(t);data:=bytes.Repeat([]byte("resume change"),2000);source:=filepath.Join(t.TempDir(),"change.bin");os.WriteFile(source,data,0600)
 digest,_:=shaFile(source);oldChunk:=int64(4096);body,_:=json.Marshal(InitRequest{"change.bin",int64(len(data)),oldChunk,digest})
 r,e:=request(client,token,"POST","https://"+p.Address+"/v1/uploads",bytes.NewReader(body));if e!=nil{t.Fatal(e)};var state InitResponse;if e=json.NewDecoder(r.Body).Decode(&state);e!=nil{t.Fatal(e)};r.Body.Close()
 info,_:=os.Stat(source);abs,_:=filepath.Abs(source)
 key:=sha256.Sum256([]byte(p.Address+"|"+p.Fingerprint+"|"+abs+"|"+strconv.FormatInt(info.Size(),10)+"|"+strconv.FormatInt(info.ModTime().UnixNano(),10)+"|"+digest+"|"+strconv.FormatInt(oldChunk,10)))
 dir,_:=clientStateDir();if e=storeJSON(filepath.Join(dir,hex.EncodeToString(key[:])+".json"),state);e!=nil{t.Fatal(e)}
 if e=sendFileWithOptions(source,"local",8192,2);e!=nil{t.Fatal(e)}
 got,e:=os.ReadFile(filepath.Join(root,"change.bin"));if e!=nil || !bytes.Equal(got,data){t.Fatal("changed chunk retry failed",e)}
}
func TestHTTPSProxyUsesIndependentTLS(t *testing.T){
 root,p,token,_:=testReceiver(t);os.WriteFile(filepath.Join(root,"proxy.bin"),[]byte("test"),0600)
 cert,_,e:=makeCert(t.TempDir());if e!=nil{t.Fatal(e)};parsed,e:=x509.ParseCertificate(cert.Certificate[0]);if e!=nil{t.Fatal(e)};roots:=x509.NewCertPool();roots.AddCert(parsed)
 var offered atomic.Int32
 proxy:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.TLS!=nil{offered.Store(int32(len(r.TLS.PeerCertificates)))}
  if r.Method!="CONNECT" || r.Host!=p.Address{http.Error(w,"wrong CONNECT",400);return}
  upstream,e:=net.Dial("tcp",p.Address);if e!=nil{http.Error(w,"connect failed",502);return}
  conn,rw,e:=w.(http.Hijacker).Hijack();if e!=nil{upstream.Close();return}
  fmt.Fprint(rw,"HTTP/1.1 200 Connection Established\r\n\r\n");rw.Flush()
  go func(){defer upstream.Close();io.Copy(upstream,rw)}()
  go func(){defer conn.Close();io.Copy(conn,upstream)}()
 }));proxy.TLS=&tls.Config{Certificates:[]tls.Certificate{cert},ClientAuth:tls.RequestClientCert};proxy.StartTLS();defer proxy.Close()
 old:=activeNetwork;activeNetwork=networkOptions{Proxy:proxy.URL};defer func(){activeNetwork=old}()
 client,e:=clientFor(p,token);if e!=nil{t.Fatal(e)};defer client.CloseIdleConnections()
 client.Transport.(*http.Transport).TLSClientConfig.Certificates=[]tls.Certificate{auditIdentity(t,false)}
 if e=configureHTTPTransportWithProxyRoots(client.Transport.(*http.Transport),roots);e!=nil{t.Fatal(e)}
 r,e:=request(client,token,"HEAD","https://"+p.Address+"/v1/files/proxy.bin",nil);if e!=nil{t.Fatal(e)};r.Body.Close();if r.StatusCode!=200{t.Fatal(r.Status)}
 if offered.Load()!=0{t.Fatal("XER identity was offered to outer proxy TLS")}
 p.Fingerprint=strings.Repeat("0",64);bad,e:=clientFor(p,token);if e!=nil{t.Fatal(e)};defer bad.CloseIdleConnections();configureHTTPTransportWithProxyRoots(bad.Transport.(*http.Transport),roots)
 if r,e=request(bad,token,"HEAD","https://"+p.Address+"/v1/files/proxy.bin",nil);e==nil{r.Body.Close();t.Fatal("inner receiver pin mismatch accepted")}
}
func TestProxyFailureHasNoDirectConnection(t *testing.T){
 var accepts atomic.Int32
 origin:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(200)}));origin.Config.ConnState=func(_ net.Conn,state http.ConnState){if state==http.StateNew{accepts.Add(1)}};origin.StartTLS();defer origin.Close()
 p:=Profile{strings.TrimPrefix(origin.URL,"https://"),fingerprint(origin.TLS.Certificates[0].Certificate[0])}
 dead,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil{t.Fatal(e)};address:=dead.Addr().String();dead.Close()
 old:=activeNetwork;activeNetwork=networkOptions{Proxy:"http://"+address};defer func(){activeNetwork=old}()
 client,e:=clientFor(p,"explicit-test-token");if e!=nil{t.Fatal(e)};defer client.CloseIdleConnections()
 if r,e:=client.Get(origin.URL);e==nil{r.Body.Close();t.Fatal("unavailable proxy accepted")}
 if accepts.Load()!=0{t.Fatal("direct fallback contacted the receiver")}
}
func TestProxyHeadersAndHandshakeHaveBounds(t *testing.T){
 for _,tlsProxy:=range []bool{false,true}{t.Run(fmt.Sprint(tlsProxy),func(t *testing.T){
  ln,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil{t.Fatal(e)};defer ln.Close()
  done:=make(chan struct{});go func(){defer close(done);c,e:=ln.Accept();if e!=nil{return};defer c.Close();c.SetDeadline(time.Now().Add(time.Second));if tlsProxy{io.Copy(io.Discard,c)}else{buf:=make([]byte,4096);c.Read(buf);io.WriteString(c,strings.Repeat("X",8192))}}()
  scheme:="http";if tlsProxy{scheme="https"};proxy,_:=validatedProxy(scheme+"://"+ln.Addr().String());ctx,cancel:=context.WithTimeout(context.Background(),100*time.Millisecond);defer cancel()
  start:=time.Now();if c,e:=dialHTTPProxyContext(ctx,proxy,"127.0.0.1:22","",nil);e==nil{c.Close();t.Fatal("invalid proxy accepted")};if time.Since(start)>time.Second{t.Fatal("proxy operation did not honor cancellation")};<-done
 })}
}

func TestDuplicateChunkConflictAndFullHash(t *testing.T){
 root,p,token,client:=testReceiver(t);data:=[]byte("original");hash:=sha256.Sum256(data)
 body,_:=json.Marshal(InitRequest{"commit.bin",int64(len(data)),int64(len(data)),hex.EncodeToString(hash[:])})
 r,e:=request(client,token,"POST","https://"+p.Address+"/v1/uploads",bytes.NewReader(body));if e!=nil{t.Fatal(e)}
 var state InitResponse;if e=json.NewDecoder(r.Body).Decode(&state);e!=nil{t.Fatal(e)};r.Body.Close()
 send:=func(payload []byte,want int){t.Helper();h:=sha256.Sum256(payload);req,_:=http.NewRequest("PUT","https://"+p.Address+"/v1/uploads/"+state.ID+"/chunks/0",bytes.NewReader(payload));req.Header.Set(headerToken,"Bearer "+token);req.Header.Set("X-Chunk-SHA256",hex.EncodeToString(h[:]));resp,e:=client.Do(req);if e!=nil{t.Fatal(e)};resp.Body.Close();if resp.StatusCode!=want{t.Fatalf("chunk status %d, want %d",resp.StatusCode,want)}}
 send(data,204);send(data,204);send([]byte("conflict"),409)
 if e=os.WriteFile(filepath.Join(root,".xer-data",state.ID+".part"),[]byte("corrupt!"),0600);e!=nil{t.Fatal(e)}
 r,e=request(client,token,"POST","https://"+p.Address+"/v1/uploads/"+state.ID+"/complete",nil);if e!=nil{t.Fatal(e)};r.Body.Close();if r.StatusCode!=422{t.Fatal("full digest corruption accepted",r.Status)}
 if _,e=os.Stat(filepath.Join(root,"commit.bin"));!os.IsNotExist(e){t.Fatal("corrupt upload was published")}
}
func TestDownloadRefusesDestinationCreatedDuringTransfer(t *testing.T){
 isolateUserState(t);t.Setenv("XER_TOKEN","local-test-token");t.Setenv("XER_TOKEN_FILE","")
 dir:=t.TempDir();dest:=filepath.Join(dir,"out.bin");data:=[]byte("remote data");digest:=sha256.Sum256(data)
 ts:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("X-File-SHA256",hex.EncodeToString(digest[:]));w.Header().Set("Content-Length",strconv.Itoa(len(data)))
  if r.Method=="GET"{if e:=os.WriteFile(dest,[]byte("keep concurrent file"),0600);e!=nil{t.Error(e)};w.Write(data)}
 }));defer ts.Close()
 p:=Profile{strings.TrimPrefix(ts.URL,"https://"),fingerprint(ts.TLS.Certificates[0].Certificate[0])}
 if e:=updateProfiles(func(all *Profiles)error{all.Servers["race"]=p;return nil});e!=nil{t.Fatal(e)}
 if e:=getFile("race:data.bin",dest);e==nil{t.Fatal("concurrent destination was overwritten")}
 got,e:=os.ReadFile(dest);if e!=nil || string(got)!="keep concurrent file"{t.Fatal("concurrent destination modified",e)}
}

func TestJSONRejectsTrailingUnknownAndOversizedData(t *testing.T){
 for _,payload:=range []string{`{"nonce":"a","extra":true}`,`{"nonce":"a"}{}`,strings.Repeat(" ",65537)}{
  req:=httptest.NewRequest("POST","/",strings.NewReader(payload));var hello pairHello
  if e:=readJSON(req,&hello);e==nil{t.Fatal("malformed JSON accepted")}
 }
}
func TestCanceledCompletionLeavesPartial(t *testing.T){
 path:=filepath.Join(t.TempDir(),"part");if e:=writeExclusive(path,[]byte("disposable"));e!=nil{t.Fatal(e)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if _,e:=shaFileContext(ctx,path);e==nil{t.Fatal("hashing ignored cancellation")}
 if _,e:=os.Stat(path);e!=nil{t.Fatal("canceled hashing deleted resumable state",e)}
}

func TestRecoveryAfterLinkBeforeCleanup(t *testing.T){
 root:=t.TempDir();if e:=privateDir(filepath.Join(root,".xer-data"));e!=nil{t.Fatal(e)}
 srv:=&Server{root:root};id:=strings.Repeat("a",32);data:=[]byte("interrupted commit");hash:=sha256.Sum256(data)
 u:=Upload{ID:id,Name:"committed.bin",Size:int64(len(data)),ChunkSize:int64(len(data)),SHA256:hex.EncodeToString(hash[:]),Received:map[int64]string{0:hex.EncodeToString(hash[:])}}
 if e:=writeExclusive(srv.partPath(id),data);e!=nil{t.Fatal(e)};if e:=storeJSON(srv.statePath(id),u);e!=nil{t.Fatal(e)}
 if e:=os.Link(srv.partPath(id),filepath.Join(root,u.Name));e!=nil{t.Skip(e)}
 if e:=writeExclusive(filepath.Join(root,".xer-data",".xer-chunk-crashed"),[]byte("temporary"));e!=nil{t.Fatal(e)}
 if e:=srv.recoverState();e!=nil{t.Fatal(e)}
 if _,e:=os.Stat(srv.statePath(id));!os.IsNotExist(e){t.Fatal("committed metadata not cleared",e)}
 f,e:=openDownloadSource(root,u.Name);if e!=nil{t.Fatal("recovered destination cannot be safely served",e)};f.Close()
 if _,e:=os.Stat(filepath.Join(root,".xer-data",".xer-chunk-crashed"));!os.IsNotExist(e){t.Fatal("orphan spool not removed")}
}
