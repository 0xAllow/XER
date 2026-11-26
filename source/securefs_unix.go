//go:build linux || darwin

package main

import (
 "errors"
 "os"
 "path/filepath"
 "syscall"
)

func validateDirectory(st os.FileInfo, private bool) error {
 raw, ok := st.Sys().(*syscall.Stat_t)
 if !ok || raw.Uid != uint32(os.Geteuid()) { return errors.New("directory is not owned by this account") }
 mask := os.FileMode(0022)
 if private { mask = 0077 }
 if st.Mode().Perm()&mask != 0 { return errors.New("directory permissions allow other accounts access") }
 return nil
}
func protectPath(_ string, _ bool) error { return nil }
func safeReadFlags() int { return syscall.O_NOFOLLOW|syscall.O_NONBLOCK }
func validateOpenFile(f *os.File, private bool) error {
 st, err := f.Stat(); if err != nil { return err }
 if !st.Mode().IsRegular() { return errors.New("file is not regular") }
 raw, ok := st.Sys().(*syscall.Stat_t)
 if !ok || raw.Nlink != 1 { return errors.New("hard-linked files are not accepted") }
 if private && (raw.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0077 != 0) { return errors.New("state file must be owner-only") }
 return nil
}
func openPrivate(path string, flags int) (*os.File, error) {
 if flags&os.O_TRUNC != 0 { return nil, errors.New("truncate requires an already verified handle") }
 f, err := os.OpenFile(path, flags|safeReadFlags(), 0600)
 if err != nil { return nil, err }
 if err = validateOpenFile(f, true); err != nil { f.Close(); return nil, err }
 return f, nil
}
func lockHandle(f *os.File) error {
 err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
 if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) { return errStateBusy }
 return err
}
func syncDirectory(path string) error {
 f, err := os.Open(path); if err != nil { return err }; defer f.Close(); return f.Sync()
}

func checkDestinationACL(path string) error {
 absolute,err:=filepath.Abs(path);if err!=nil{return err}
 resolved,err:=filepath.EvalSymlinks(absolute);if err!=nil{return err}
 for _,start:=range []string{absolute,resolved}{
  for current:=start;;current=filepath.Dir(current){
   st,err:=os.Lstat(current);if err!=nil{return err};raw,ok:=st.Sys().(*syscall.Stat_t)
   if !ok || (raw.Uid!=0 && raw.Uid!=uint32(os.Geteuid())){return errors.New("directory ancestry is controlled by another account")}
   if st.Mode()&os.ModeSymlink==0 && st.Mode().Perm()&0022!=0 && !(raw.Uid==0 && st.Mode()&os.ModeSticky!=0){return errors.New("directory ancestry allows replacement by another account")}
   if filepath.Dir(current)==current{break}
  }
 }
 return nil
}
