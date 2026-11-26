package main

import (
 "errors"
 "fmt"
 "io"
 "net/http"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "time"
)

type receiverLimits struct {
 MaxFile int64
 MaxChunks int64
 MaxPending int
 MaxFiles int
 MaxStorage int64
 Concurrent int
 BodyTimeout time.Duration
 UploadTTL time.Duration
}
func defaultReceiverLimits() receiverLimits { return receiverLimits{64<<30,65536,128,10000,128<<30,8,2*time.Minute,24*time.Hour} }
func (s *Server) initLimits() {
 s.initOnce.Do(func(){
  d:=defaultReceiverLimits()
  if s.limits.MaxFile<=0 {s.limits.MaxFile=d.MaxFile};if s.limits.MaxChunks<=0 {s.limits.MaxChunks=d.MaxChunks}
  if s.limits.MaxPending<=0 {s.limits.MaxPending=d.MaxPending};if s.limits.MaxFiles<=0 {s.limits.MaxFiles=d.MaxFiles}
  if s.limits.MaxStorage<=0 {s.limits.MaxStorage=d.MaxStorage};if s.limits.Concurrent<=0 {s.limits.Concurrent=d.Concurrent}
  if s.limits.BodyTimeout<=0 {s.limits.BodyTimeout=d.BodyTimeout};if s.limits.UploadTTL<=0 {s.limits.UploadTTL=d.UploadTTL}
  s.slots=make(chan struct{},s.limits.Concurrent)
 })
}
func chunkCount(size, chunk int64) int64 { if size<=0 || chunk<=0 {return 0};n:=size/chunk;if size%chunk!=0 {n++};return n }
func (s *Server) validateUpload(u Upload,id string) error {
 s.initLimits()
 if u.ID!=id || !validName(u.Name) || u.Size<0 || u.Size>s.limits.MaxFile || u.ChunkSize<=0 || u.ChunkSize>maxChunk || !goodHash(u.SHA256) || chunkCount(u.Size,u.ChunkSize)>s.limits.MaxChunks || u.Received==nil {return errors.New("invalid stored upload metadata")}
 for index,digest:=range u.Received {if index<0 || index>=chunkCount(u.Size,u.ChunkSize) || !goodHash(digest) {return errors.New("invalid stored chunk metadata")}}
 return nil
}
func (s *Server) uploadMutex(id string) *sync.Mutex {
 value,_:=s.uploadLocks.LoadOrStore(id,&sync.Mutex{});return value.(*sync.Mutex)
}
// Called under s.mu to serialize quota reservations, not chunk writes.
func (s *Server) reserveUpload(size int64) error {
 s.initLimits();var used int64;files:=0;pending:=0
 root,err:=os.Open(s.root);if err!=nil {return err};defer root.Close()
 for {entries,e:=root.ReadDir(128);if e!=nil && !errors.Is(e,io.EOF) {return e}
  for _,entry:=range entries {if entry.Name()==".xer-data" {continue};files++;if files>=s.limits.MaxFiles {return errors.New("receiver file-count quota reached")};st,se:=entry.Info();if se!=nil {return se};if st.Mode().IsRegular(){if st.Size()>s.limits.MaxStorage-used {return errors.New("receiver storage quota reached")};used+=st.Size()}}
  if errors.Is(e,io.EOF){break}
 }
 state,err:=os.Open(filepath.Join(s.root,".xer-data"));if err!=nil{return err};defer state.Close()
 for {entries,e:=state.ReadDir(128);if e!=nil && !errors.Is(e,io.EOF){return e}
  for _,entry:=range entries {
   name:=entry.Name();if !strings.HasSuffix(name,".json") || len(name)!=37 || !isHex(name[:32]) {continue}
   id:=name[:32];st,se:=entry.Info();if se!=nil {return se}
   if time.Since(st.ModTime())>s.limits.UploadTTL {
    mu:=s.uploadMutex(id)
    if mu.TryLock(){
     current,ce:=os.Stat(s.statePath(id))
     if ce==nil && time.Since(current.ModTime())>s.limits.UploadTTL {
      pe:=os.Remove(s.partPath(id));if pe!=nil && !errors.Is(pe,os.ErrNotExist){mu.Unlock();return pe}
      if ce=os.Remove(s.statePath(id));ce!=nil {mu.Unlock();return ce}
      mu.Unlock();s.uploadLocks.Delete(id);continue
     };mu.Unlock()
    }
   }
   u,ue:=s.loadUpload(id);if ue!=nil {return fmt.Errorf("invalid pending upload %s: %w",id,ue)}
   pending++;if pending>=s.limits.MaxPending {return errors.New("receiver pending-upload quota reached")}
   if u.Size>s.limits.MaxStorage-used {return errors.New("receiver storage quota reached")};used+=u.Size
  }
  if errors.Is(e,io.EOF){break}
 }
 if size>s.limits.MaxStorage-used {return errors.New("receiver storage quota reached")}
 return nil
}

type deadlineResponse struct {http.ResponseWriter; timeout time.Duration}
func (w deadlineResponse) Unwrap() http.ResponseWriter {return w.ResponseWriter}
func (w deadlineResponse) Write(b []byte)(int,error){
 _=http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.timeout))
 return w.ResponseWriter.Write(b)
}
func (s *Server) limitResponse(next http.Handler) http.Handler {
 s.initLimits()
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){next.ServeHTTP(deadlineResponse{w,s.limits.BodyTimeout},r)})
}
