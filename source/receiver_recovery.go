package main

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

// Only called before listening, with the receiver's kernel singleton lock held.
// Application-owned spools from a dead process cannot still be active here.
func(s *Server)recoverState()error{
 s.initLimits();dir:=filepath.Join(s.root,".xer-data");f,err:=os.Open(dir);if err!=nil{return err};defer f.Close()
 var names []string
 for {entries,e:=f.ReadDir(128);if e!=nil && !errors.Is(e,io.EOF){return e}
  for _,entry:=range entries{names=append(names,entry.Name());if len(names)>s.limits.MaxPending*2+256{return errors.New("too many receiver state entries; inspect old state before startup")}}
  if errors.Is(e,io.EOF){break}
 }
 for _,name:=range names{
  temporary:=strings.HasPrefix(name,".xer-chunk-") || (strings.HasPrefix(name,".xer-") && strings.HasSuffix(name,".tmp")) || name=="pending-pair.json"
  if temporary{
   file,e:=openPrivate(filepath.Join(dir,name),os.O_RDONLY);if e!=nil{return e};file.Close()
   if e=os.Remove(filepath.Join(dir,name));e!=nil{return e};continue
  }
  if len(name)==37 && strings.HasSuffix(name,".part") && isHex(name[:32]){
   if _,e:=os.Lstat(s.statePath(name[:32]));errors.Is(e,os.ErrNotExist){
    file,e:=openPrivate(filepath.Join(dir,name),os.O_RDONLY);if e!=nil{return e};file.Close();if e=os.Remove(filepath.Join(dir,name));e!=nil{return e}
   }else if e!=nil{return e}
  }
 }
 for _,name:=range names{
  if len(name)!=37 || !strings.HasSuffix(name,".json") || !isHex(name[:32]){continue}
  id:=name[:32];u,e:=s.loadUpload(id);if e!=nil{return fmt.Errorf("invalid receiver state %s: %w",id,e)}
  part,partErr:=os.Lstat(s.partPath(id));dest,destErr:=os.Lstat(filepath.Join(s.root,u.Name))
  if partErr!=nil && !errors.Is(partErr,os.ErrNotExist){return partErr};if destErr!=nil && !errors.Is(destErr,os.ErrNotExist){return destErr}
  linked:=partErr==nil && destErr==nil && part.Mode().IsRegular() && dest.Mode().IsRegular() && os.SameFile(part,dest)
  if linked || (errors.Is(partErr,os.ErrNotExist) && destErr==nil){
   if e=s.verifyRecoveredDestination(u);e!=nil{return e}
   if linked{if e=os.Remove(s.partPath(id));e!=nil{return e}}
   if e=os.Remove(s.statePath(id));e!=nil{return e}
  }else if errors.Is(partErr,os.ErrNotExist) && errors.Is(destErr,os.ErrNotExist){
   // No published destination and no data: retry must create a fresh upload.
   if e=os.Remove(s.statePath(id));e!=nil{return e}
  }
 }
 if err=syncDirectory(dir);err!=nil{return err};return syncDirectory(s.root)
}
func(s *Server)verifyRecoveredDestination(u Upload)error{
 root,err:=os.OpenRoot(s.root);if err!=nil{return err};defer root.Close()
 // A valid interrupted commit has two links to the same inode, so this
 // recovery-only read intentionally does not require link count == 1.
 f,err:=root.OpenFile(u.Name,os.O_RDONLY|safeReadFlags(),0);if err!=nil{return err};defer f.Close()
 st,err:=f.Stat();if err!=nil{return err};if !st.Mode().IsRegular() || st.Size()!=u.Size{return errors.New("interrupted commit has wrong size/type")}
 h:=sha256.New();if _,err=io.Copy(h,f);err!=nil{return err};if hex.EncodeToString(h.Sum(nil))!=u.SHA256{return errors.New("interrupted commit digest mismatch; inspect published file")}
 return nil
}
