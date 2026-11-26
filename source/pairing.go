package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "time"
)

const maxTrustedDevices = 256
const pairingTTL = 2*time.Minute

type pairSession struct {
 ID string `json:"id"`
 Client string `json:"client"`
 Server string `json:"server"`
 Nonce string `json:"nonce"`
 Code string `json:"code"`
 Expires time.Time `json:"expires"`
 Approved bool `json:"approved"`
}
type pairHello struct {Nonce string `json:"nonce"`}
func pairPath(root string) string {return filepath.Join(root,".xer-data","pending-pair.json")}
func trustLock(root string)(*fileLock,error){return acquireLock(filepath.Join(root,".xer-data","trust.lock"))}
func identity()(tls.Certificate,error){
 d,err:=configDir();if err!=nil{return tls.Certificate{},err}
 c,_,err:=makeCert(filepath.Join(d,"identity"));return c,err
}
func fingerprint(der []byte)string{h:=sha256.Sum256(der);return hex.EncodeToString(h[:])}
// Kept for compatibility with the original code-binding unit test. Protocol v2
// also binds two nonces through pairSessionCode, not this static display alone.
func pairCode(serverDER,clientDER []byte)string{
 h:=sha256.New();h.Write([]byte("xer-pair-v1\x00"));h.Write(serverDER);h.Write(clientDER)
 return strings.ToUpper(hex.EncodeToString(h.Sum(nil)[:10]))
}
func pairSessionCode(serverDER,clientDER []byte,id,nonce string)string{
 h:=sha256.New();h.Write([]byte("xer-pair-v2\x00"));h.Write(serverDER);h.Write(clientDER);h.Write([]byte(id));h.Write([]byte(nonce))
 return strings.ToUpper(hex.EncodeToString(h.Sum(nil)[:10]))
}
func confirm(prompt string)bool{fmt.Print(prompt," [type YES]: ");var v string;_,e:=fmt.Fscanln(os.Stdin,&v);return e==nil && v=="YES"}
func certValid(c *x509.Certificate)error{now:=time.Now();if c==nil || now.Before(c.NotBefore)||now.After(c.NotAfter){return errors.New("certificate not valid at this time")};return nil}
func trustedPath(root string)string{return filepath.Join(root,".xer-data","trusted.json")}
func readTrusted(root string)(map[string]bool,error){
 clients:=map[string]bool{};e:=readPrivateJSON(trustedPath(root),&clients,65536)
 if errors.Is(e,os.ErrNotExist){return clients,nil};if e!=nil{return nil,e}
 if clients==nil || len(clients)>maxTrustedDevices{return nil,errors.New("invalid trust database")}
 for fp:=range clients{if !goodHash(fp){return nil,errors.New("invalid trusted fingerprint")}}
 return clients,nil
}
func (s *Server) paired(r *http.Request)bool{
 if r.TLS==nil || len(r.TLS.PeerCertificates)!=1 || certValid(r.TLS.PeerCertificates[0])!=nil{return false}
 clients,e:=readTrusted(s.root);return e==nil && clients[fingerprint(r.TLS.PeerCertificates[0].Raw)]
}
func (s *Server) pair(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 if r.Method!=http.MethodPost{http.Error(w,"method not allowed",405);return}
 if !time.Now().Before(s.pairingUntil){http.Error(w,"pairing disabled; start receiver with --pair-window",403);return}
 if r.TLS==nil || len(r.TLS.PeerCertificates)!=1 || certValid(r.TLS.PeerCertificates[0])!=nil{http.Error(w,"valid client certificate required",401);return}
 _=http.NewResponseController(w).SetReadDeadline(time.Now().Add(10*time.Second))
 var hello pairHello;if readJSON(r,&hello)!=nil || len(hello.Nonce)!=64 || !isHex(hello.Nonce){http.Error(w,"invalid pairing nonce",400);return}
 if !s.pairMu.TryLock(){http.Error(w,"pairing busy",503);return};defer s.pairMu.Unlock()
 lock,e:=trustLock(s.root);if e!=nil{http.Error(w,"pairing busy",503);return};defer lock.Close()
 var pending pairSession
 e=readPrivateJSON(pairPath(s.root),&pending,65536)
 if e==nil && time.Now().Before(pending.Expires){
  if pending.Client==fingerprint(r.TLS.PeerCertificates[0].Raw) && pending.Nonce==hello.Nonce{writeJSON(w,202,pending);return}
  http.Error(w,"one pairing session is already pending",409);return
 }
 if e!=nil && !errors.Is(e,os.ErrNotExist){http.Error(w,"pairing state error",500);return}
 if s.pairCount>=10{http.Error(w,"pairing attempt limit reached; restart the explicit window",429);return}
 id,e:=randomHex(32);if e!=nil{http.Error(w,"random source error",500);return}
 expires:=time.Now().Add(pairingTTL);if s.pairingUntil.Before(expires){expires=s.pairingUntil}
 pending=pairSession{ID:id,Client:fingerprint(r.TLS.PeerCertificates[0].Raw),Server:fingerprint(s.certDER),Nonce:hello.Nonce,Code:pairSessionCode(s.certDER,r.TLS.PeerCertificates[0].Raw,id,hello.Nonce),Expires:expires}
 if e=storeJSON(pairPath(s.root),pending);e!=nil{http.Error(w,"pairing state error",500);return}
 s.pairCount++
 fmt.Printf("\nPairing request from %s\nCompare code: %s\nApprove only a matching expected request, in this receiver directory:\nxer trust approve %s %s\nExpires: %s\n",r.RemoteAddr,pending.Code,pending.ID,pending.Code,pending.Expires.Format(time.RFC3339))
 writeJSON(w,202,pending)
}
func (s *Server) pairAction(w http.ResponseWriter,r *http.Request){
 _=http.NewResponseController(w).SetReadDeadline(time.Now().Add(10*time.Second))
 w.Header().Set("Cache-Control","no-store")
 if r.Method!=http.MethodPost && r.Method!=http.MethodDelete{http.Error(w,"method not allowed",405);return}
 id:=strings.TrimPrefix(r.URL.Path,"/v1/pair/")
 if len(id)!=64 || !isHex(id){http.NotFound(w,r);return}
 if r.TLS==nil || len(r.TLS.PeerCertificates)!=1 || certValid(r.TLS.PeerCertificates[0])!=nil{http.Error(w,"valid client identity required",401);return}
 lock,e:=trustLock(s.root);if e!=nil{http.Error(w,"pairing busy",503);return};defer lock.Close()
 var session pairSession
 if e=readPrivateJSON(pairPath(s.root),&session,65536);e!=nil || session.ID!=id || session.Client!=fingerprint(r.TLS.PeerCertificates[0].Raw) || session.Server!=fingerprint(s.certDER){http.NotFound(w,r);return}
 if !time.Now().Before(session.Expires) || !time.Now().Before(s.pairingUntil){
  if e=os.Remove(pairPath(s.root));e!=nil && !errors.Is(e,os.ErrNotExist){http.Error(w,"state cleanup error",500);return}
  http.Error(w,"pairing expired",410);return
 }
 if r.Method==http.MethodDelete{
  if e=os.Remove(pairPath(s.root));e!=nil{http.Error(w,"state cleanup error",500);return};w.WriteHeader(204);return
 }
 if !session.Approved{w.WriteHeader(202);return}
 clients,e:=readTrusted(s.root);if e!=nil{http.Error(w,"trust database error",500);return}
 if !clients[session.Client] && len(clients)>=maxTrustedDevices{http.Error(w,"trusted-device limit reached",409);return}
 // The POST is the sender's explicit approval, on a TLS connection proving
 // possession of the same key. The receiver approved this exact random session.
 clients[session.Client]=true
 if e=storeJSON(trustedPath(s.root),clients);e!=nil{http.Error(w,"trust database error",500);return}
 if e=os.Remove(pairPath(s.root));e!=nil{http.Error(w,"paired; pending-state cleanup failed",500);return}
 w.WriteHeader(204)
}
func address(alias string)(string,error){
 profiles,e:=loadProfiles();if e!=nil{return "",e};if p,ok:=profiles.Servers[alias];ok{return p.Address,nil}
 if alias=="" || strings.ContainsAny(alias,"/\\\n\r\x00 \t@?#"){return "",errors.New("invalid address")}
 if host,port,e:=net.SplitHostPort(alias);e==nil{n,pe:=strconv.Atoi(port);if host=="" || pe!=nil || n<1 || n>65535{return "",errors.New("invalid receiver address")};return alias,nil}
 if strings.Contains(alias,":"){return "",errors.New("use HOST:PORT or IPv6 [ADDRESS]:PORT")}
 return net.JoinHostPort(alias,strconv.Itoa(activeSettings.Port)),nil
}
func pairAddress(alias string)(Profile,error){
 adr,e:=address(alias);if e!=nil{return Profile{},e};id,e:=identity();if e!=nil{return Profile{},e}
 var mu sync.Mutex;var serverDER []byte;serverPin:=""
 tr:=&http.Transport{TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS13,InsecureSkipVerify:true,Certificates:[]tls.Certificate{id},VerifyConnection:func(cs tls.ConnectionState)error{
  if len(cs.PeerCertificates)!=1{return errors.New("receiver certificate missing")};c:=cs.PeerCertificates[0];if e:=certValid(c);e!=nil{return e}
  mu.Lock();defer mu.Unlock();pin:=fingerprint(c.Raw)
  if serverPin!="" && serverPin!=pin{return errors.New("receiver identity changed during pairing")}
  serverPin=pin;serverDER=append([]byte(nil),c.Raw...);return nil
 }},TLSHandshakeTimeout:15*time.Second,ResponseHeaderTimeout:20*time.Second}
 if e=configureHTTPTransport(tr);e!=nil{return Profile{},e};defer tr.CloseIdleConnections()
 client:=&http.Client{Transport:tr,Timeout:30*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("redirect forbidden")}}
 nonce,e:=randomHex(32);if e!=nil{return Profile{},e};body,_:=json.Marshal(pairHello{nonce})
 ctx,cancel:=context.WithTimeout(context.Background(),pairingTTL);defer cancel()
 req,e:=http.NewRequestWithContext(ctx,"POST","https://"+adr+"/v1/pair",bytes.NewReader(body));if e!=nil{return Profile{},e}
 resp,e:=client.Do(req);if e!=nil{return Profile{},e}
 if e=checkStatus(resp,202);e!=nil{resp.Body.Close();return Profile{},e}
 var session pairSession;e=json.NewDecoder(io.LimitReader(resp.Body,65536)).Decode(&session);resp.Body.Close();if e!=nil{return Profile{},e}
 mu.Lock();pin:=serverPin;der:=append([]byte(nil),serverDER...);mu.Unlock()
 if len(session.ID)!=64 || !isHex(session.ID) || session.Nonce!=nonce || session.Server!=pin || session.Client!=fingerprint(id.Certificate[0]) || !time.Now().Before(session.Expires) || session.Expires.After(time.Now().Add(pairingTTL+time.Second)){return Profile{},errors.New("invalid pairing challenge")}
 code:=pairSessionCode(der,id.Certificate[0],session.ID,nonce)
 if session.Code!=code{return Profile{},errors.New("pairing transcript mismatch")}
 endpoint:="https://"+adr+"/v1/pair/"+session.ID
 fmt.Printf("\nPairing with %s\nCompare this code on both devices: %s\nReceiver approval: xer trust approve %s %s\n",adr,code,session.ID,code)
 if !confirm("Do both displays match over your trusted channel?"){
  req,_:=http.NewRequestWithContext(ctx,"DELETE",endpoint,nil);if req!=nil{if response,err:=client.Do(req);err==nil{response.Body.Close()}}
  return Profile{},errors.New("pairing declined; no sender trust saved")
 }
 for {
  if !time.Now().Before(session.Expires){return Profile{},errors.New("pairing expired")}
  req,e=http.NewRequestWithContext(ctx,"POST",endpoint,nil);if e!=nil{return Profile{},e};resp,e=client.Do(req);if e!=nil{return Profile{},e}
  status:=resp.StatusCode
  if status!=202 && status!=204{e=checkStatus(resp,204)};resp.Body.Close();if e!=nil{return Profile{},e}
  if status==204{break}
  select{case <-ctx.Done():return Profile{},ctx.Err();case <-time.After(500*time.Millisecond):}
 }
 profile:=Profile{Address:adr,Fingerprint:pin}
 if e=updateProfiles(func(p *Profiles)error{p.Servers[alias]=profile;return nil});e!=nil{return Profile{},e}
 fmt.Println("Both approvals complete; trusted receiver saved.");return profile,nil
}
func getOrPair(alias string)(Profile,error){p,e:=loadProfiles();if e!=nil{return Profile{},e};if known,ok:=p.Servers[alias];ok{return known,nil};return pairAddress(alias)}
func clientIdentityTLS(c *tls.Config)error{id,e:=identity();if e!=nil{return e};c.Certificates=[]tls.Certificate{id};return nil}
func updateProfiles(update func(*Profiles)error)error{
 d,e:=configDir();if e!=nil{return e};lock,e:=acquireLock(filepath.Join(d,"connections.lock"));if e!=nil{return e};defer lock.Close()
 p,e:=loadProfiles();if e!=nil{return e};if e=update(&p);e!=nil{return e};path,e:=configFile();if e!=nil{return e};return storeJSON(path,p)
}
func trustCommand(args []string)error{
 if len(args)==0{return errors.New("usage: xer trust list|remove FP|approve SESSION CODE|forget ALIAS")}
 if args[0]=="forget"{if len(args)!=2{return errors.New("usage: xer trust forget ALIAS")};return updateProfiles(func(p *Profiles)error{if _,ok:=p.Servers[args[1]];!ok{return errors.New("unknown receiver alias")};delete(p.Servers,args[1]);return nil})}
 root,e:=filepath.Abs(".");if e!=nil{return e};lock,e:=trustLock(root);if e!=nil{return e};defer lock.Close()
 switch args[0]{
 case "list":
  if len(args)!=1{return errors.New("usage: xer trust list")};t,e:=readTrusted(root);if e!=nil{return e};for fp:=range t{fmt.Println(fp)};return nil
 case "remove":
  if len(args)!=2 || !goodHash(args[1]){return errors.New("usage: xer trust remove CLIENT_FINGERPRINT")};t,e:=readTrusted(root);if e!=nil{return e};delete(t,strings.ToLower(args[1]));return storeJSON(trustedPath(root),t)
 case "approve":
  if len(args)!=3 || len(args[1])!=64 || !isHex(args[1]){return errors.New("usage: xer trust approve SESSION CODE")}
  var p pairSession;if e=readPrivateJSON(pairPath(root),&p,65536);e!=nil{return e}
  if p.ID!=args[1] || !secureEqual(p.Code,strings.ToUpper(args[2])) || !time.Now().Before(p.Expires){return errors.New("wrong or expired pairing session/code")}
  p.Approved=true;if e=storeJSON(pairPath(root),p);e!=nil{return e};fmt.Println("Receiver approved this session. Sender must also confirm the matching code.");return nil
 default:return errors.New("usage: xer trust list|remove FP|approve SESSION CODE|forget ALIAS")
 }
}
