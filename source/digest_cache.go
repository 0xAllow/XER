package main
import("crypto/sha256";"encoding/hex";"errors";"io";"os")
type cachedDigest struct{info os.FileInfo;digest string}
func(s *Server)fileDigest(name string,f *os.File)(string,error){
 st,err:=f.Stat();if err!=nil{return "",err}
 s.cacheMu.Lock();old,ok:=s.digests[name];s.cacheMu.Unlock()
 if ok && os.SameFile(old.info,st) && old.info.Size()==st.Size() && old.info.ModTime()==st.ModTime(){return old.digest,nil}
 h:=sha256.New();if _,err=io.Copy(h,f);err!=nil{return "",err}
 after,err:=f.Stat();if err!=nil{return "",err}
 if after.Size()!=st.Size() || after.ModTime()!=st.ModTime(){return "",errors.New("file changed while hashing")}
 digest:=hex.EncodeToString(h.Sum(nil))
 s.cacheMu.Lock();if len(s.digests)>=32{s.digests=nil};if s.digests==nil{s.digests=map[string]cachedDigest{}};s.digests[name]=cachedDigest{st,digest};s.cacheMu.Unlock()
 return digest,nil
}
