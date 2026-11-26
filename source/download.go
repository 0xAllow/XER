package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "net/url"
 "os"
 "path/filepath"
 "strconv"
 "strings"
)

type downloadMetadata struct {
 Address string `json:"address"`
 Pin string `json:"pin"`
 Name string `json:"name"`
 Size int64 `json:"size"`
 Digest string `json:"digest"`
}

type downloadStage struct {
 parent *os.Root
 root *os.Root
 lock *os.File
 name string
 target string
}
func (s *downloadStage) Close() { s.lock.Close(); s.root.Close(); s.parent.Close() }

func newDownloadStage(dest string, meta downloadMetadata) (*downloadStage, error) {
 absolute, err := filepath.Abs(dest); if err != nil { return nil, err }
 parentPath, target := filepath.Dir(absolute), filepath.Base(absolute)
 if err = trustedDirectory(parentPath); err != nil { return nil, err }
 parent, err := os.OpenRoot(parentPath); if err != nil { return nil, err }
 ok := false
 defer func(){ if !ok { parent.Close() } }()
 key := sha256.Sum256([]byte(absolute+"\x00"+meta.Address+"\x00"+meta.Pin+"\x00"+meta.Name))
 name := ".xer-download-"+hex.EncodeToString(key[:16])
 if err = parent.Mkdir(name,0700); err != nil && !errors.Is(err,os.ErrExist) { return nil,err }
 before, err := parent.Lstat(name)
 if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 { return nil,errors.New("unsafe download staging directory") }
 if err = validateDirectory(before,true); err != nil { return nil,err }
 if err = protectPath(filepath.Join(parentPath,name),true); err != nil { return nil,err }
 root, err := parent.OpenRoot(name); if err != nil { return nil,err }
 defer func(){ if !ok { root.Close() } }()
 after, err := root.Stat(".")
 if err != nil || !os.SameFile(before,after) { return nil,errors.New("staging directory changed") }
 lock, err := root.OpenFile("lock",os.O_CREATE|os.O_RDWR|safeReadFlags(),0600)
 if err != nil { return nil,err }
 defer func(){ if !ok { lock.Close() } }()
 if err = validateOpenFile(lock,true); err != nil { return nil,err }
 if err = lockHandle(lock); err != nil { return nil,err }
 var old downloadMetadata
 f, e := root.OpenFile("metadata.json",os.O_RDONLY|safeReadFlags(),0)
 if e == nil {
  if err = validateOpenFile(f,true); err == nil { err = json.NewDecoder(io.LimitReader(f,65536)).Decode(&old) }; f.Close()
  if err != nil { return nil,err }
  if old != meta { return nil,fmt.Errorf("remote identity or content changed; close transfers and remove %s to restart",filepath.Join(parentPath,name)) }
 } else if !errors.Is(e,os.ErrNotExist) { return nil,e
 } else {
  // Never adopt a pre-existing unbound partial, including legacy .xer-part.
  if _,e = root.Lstat("part"); !errors.Is(e,os.ErrNotExist) { return nil,errors.New("unbound download partial refused") }
  b,_ := json.Marshal(meta)
  f,e = root.OpenFile("metadata.json",os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
  if e != nil { return nil,e }
  if _,err=f.Write(b); err==nil {err=f.Sync()};closeErr:=f.Close();if err==nil {err=closeErr};if err!=nil {return nil,err}
 }
 ok=true
 return &downloadStage{parent:parent,root:root,lock:lock,name:name,target:target},nil
}

func getFile(source, dest string) error {
 colon:=strings.LastIndexByte(source,':')
 if colon<1 || colon==len(source)-1 {return errors.New("expected SERVER:FILENAME")}
 alias,name:=source[:colon],source[colon+1:]
 if !validName(name) {return errors.New("invalid remote filename")}
 if dest=="" {dest=name}
 if strings.HasSuffix(dest,string(os.PathSeparator)) {dest=filepath.Join(dest,name)}
 if _,err:=os.Lstat(dest);err==nil {return errors.New("destination already exists (refusing overwrite)")} else if !errors.Is(err,os.ErrNotExist) {return err}
 p,err:=getOrPair(alias);if err!=nil {return err}
 token,err:=optionalToken();if err!=nil {return err}
 client,err:=clientFor(p,token);if err!=nil {return err};defer client.CloseIdleConnections()
 endpoint:="https://"+p.Address+"/v1/files/"+url.PathEscape(name)
 resp,err:=request(client,token,"HEAD",endpoint,nil);if err!=nil {return err}
 if err=checkStatus(resp,200);err!=nil {resp.Body.Close();return err}
 digest:=resp.Header.Get("X-File-SHA256");size,parseErr:=strconv.ParseInt(resp.Header.Get("Content-Length"),10,64);resp.Body.Close()
 if parseErr!=nil || size<0 || !goodHash(digest) {return errors.New("invalid remote file metadata")}
 stage,err:=newDownloadStage(dest,downloadMetadata{p.Address,p.Fingerprint,name,size,digest});if err!=nil {return err};defer stage.Close()
 f,err:=stage.root.OpenFile("part",os.O_CREATE|os.O_RDWR|safeReadFlags(),0600);if err!=nil {return err};defer f.Close()
 if err=validateOpenFile(f,true);err!=nil {return err}
 st,err:=f.Stat();if err!=nil {return err};offset:=st.Size()
 if offset>size {return errors.New("private partial larger than remote; remove staging directory to restart")}
 if offset<size {
  req,err:=http.NewRequest("GET",endpoint,nil);if err!=nil {return err}
  req.Header.Set(headerToken,"Bearer "+token)
  if offset>0 {req.Header.Set("Range",fmt.Sprintf("bytes=%d-",offset))}
  resp,err=client.Do(req);if err!=nil {return err}
  expected:=200;if offset>0 {expected=206}
  if err=checkStatus(resp,expected);err!=nil {resp.Body.Close();return err}
  if resp.Header.Get("X-File-SHA256")!=digest {resp.Body.Close();return errors.New("remote changed between HEAD and GET")}
  if offset>0 && resp.Header.Get("Content-Range")!=fmt.Sprintf("bytes %d-%d/%d",offset,size-1,size) {resp.Body.Close();return errors.New("unexpected Content-Range")}
  if _,err=f.Seek(offset,io.SeekStart);err!=nil {resp.Body.Close();return err}
  n,copyErr:=io.Copy(f,io.LimitReader(resp.Body,size-offset+1));resp.Body.Close()
  if copyErr!=nil {return copyErr};if n!=size-offset {return fmt.Errorf("incomplete download: got %d of %d bytes",n,size-offset)}
 }
 if err=f.Sync();err!=nil {return err}
 if _,err=f.Seek(0,io.SeekStart);err!=nil {return err}
 h:=sha256.New();if _,err=io.Copy(h,f);err!=nil {return err}
 if hex.EncodeToString(h.Sum(nil))!=digest {return errors.New("download SHA-256 mismatch; private partial preserved")}
 verified,err:=f.Stat();if err!=nil {return err}
 if err=f.Close();err!=nil {return err}
 current,err:=stage.root.Lstat("part");if err!=nil || !current.Mode().IsRegular() || !os.SameFile(verified,current) {return errors.New("partial changed before publication")}
 if err=stage.parent.Link(filepath.Join(stage.name,"part"),stage.target);err!=nil {return fmt.Errorf("publish without overwrite: %w",err)}
 // After linking, part has two links; do not reopen it through validateOpenFile.
 if err=stage.root.Remove("part");err!=nil {return fmt.Errorf("download published; staging cleanup failed: %w",err)}
 if err=stage.root.Remove("metadata.json");err!=nil {return fmt.Errorf("download published; metadata cleanup failed: %w",err)}
 if err=syncDirectory(filepath.Dir(dest));err!=nil {return fmt.Errorf("download published; directory sync failed: %w",err)}
 fmt.Printf("Download complete: %s\n",dest)
 return nil
}
