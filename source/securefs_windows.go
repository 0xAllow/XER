//go:build windows

package main

import (
 "errors"
 "os"
 "os/user"
 "path/filepath"
 "syscall"
 "unsafe"
)

var advapi = syscall.NewLazyDLL("advapi32.dll")
var convertSecurity = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var setSecurity = advapi.NewProc("SetNamedSecurityInfoW")
var getDescriptorDACL = advapi.NewProc("GetSecurityDescriptorDacl")
var kernel = syscall.NewLazyDLL("kernel32.dll")
var localFree = kernel.NewProc("LocalFree")
var lockFileEx = kernel.NewProc("LockFileEx")

// Owner and SYSTEM only, protected from parent DACL inheritance. OI/CI also
// protects newly created children; POSIX mode bits alone do not set Windows ACLs.
func protectPath(path string, directory bool) error {
 if directory {if err:=checkDestinationACL(path);err!=nil{return err}} else {if err:=checkWindowsACL(path,true);err!=nil{return err}}
 u, err := user.Current(); if err != nil { return err }
 inherit := ""; if directory { inherit = "OICI" }
 sddl, err := syscall.UTF16PtrFromString("D:P(A;"+inherit+";FA;;;"+u.Uid+")(A;"+inherit+";FA;;;SY)")
 if err != nil { return err }
 var descriptor uintptr
 ok, _, callErr := convertSecurity.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
 if ok == 0 { return callErr }; defer localFree.Call(descriptor)
 name, err := syscall.UTF16PtrFromString(path); if err != nil { return err }
 var present,defaulted uint32;var acl uintptr
 ok,_,callErr=getDescriptorDACL.Call(descriptor,uintptr(unsafe.Pointer(&present)),uintptr(unsafe.Pointer(&acl)),uintptr(unsafe.Pointer(&defaulted)))
 if ok==0{return callErr};if present==0 || acl==0{return errors.New("missing private DACL")}
 result,_,_:=setSecurity.Call(uintptr(unsafe.Pointer(name)),1,uintptr(0x80000004),0,0,acl,0)
 if result!=0{return syscall.Errno(result)}
 return nil
}
func validateDirectory(_ os.FileInfo, _ bool) error { return nil }
func safeReadFlags() int { return 0 }
func validateOpenFile(f *os.File, _ bool) error {
 st, err := f.Stat(); if err != nil { return err }
 if !st.Mode().IsRegular() { return errors.New("file is not regular") }
 var info syscall.ByHandleFileInformation
 if err = syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &info); err != nil { return err }
 if info.NumberOfLinks != 1 || info.FileAttributes&0x400 != 0 { return errors.New("links and reparse points are not accepted") }
 return nil
}
func openPrivate(path string, flags int) (*os.File, error) {
 if flags&os.O_TRUNC != 0 { return nil, errors.New("truncate requires a verified handle") }
 before, statErr := os.Lstat(path)
 if statErr == nil && !before.Mode().IsRegular() { return nil, errors.New("state path is not regular") }
 if statErr != nil && !errors.Is(statErr, os.ErrNotExist) { return nil, statErr }
 if errors.Is(statErr, os.ErrNotExist) && flags&os.O_CREATE != 0 { flags |= os.O_EXCL }
 f, err := os.OpenFile(path, flags, 0600); if err != nil { return nil, err }
 after, err := f.Stat()
 if err != nil || (statErr == nil && !os.SameFile(before, after)) { f.Close(); return nil, errors.New("state path changed while opening") }
 if err = validateOpenFile(f, true); err != nil { f.Close(); return nil, err }
 if err = protectPath(path, false); err != nil { f.Close(); return nil, err }
 return f, nil
}
func lockHandle(f *os.File) error {
 var overlapped syscall.Overlapped
 ok, _, err := lockFileEx.Call(uintptr(f.Fd()), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
 if ok == 0 { if errors.Is(err, syscall.Errno(33)) { return errStateBusy }; return err }
 return nil
}
// Windows has no portable directory fsync through os.File. File data is synced;
// persistence of the final directory entry across power loss is not promised.
func syncDirectory(_ string) error { return nil }

// Conservatively reject directories writable by accounts other than this user,
// SYSTEM and Administrators. Deny ACEs are not used to excuse broad allow ACEs.
func checkDestinationACL(path string)error{
 absolute,err:=filepath.Abs(path);if err!=nil{return err}
 first:=true
 for current:=absolute;;current=filepath.Dir(current){
  if err:=checkWindowsACL(current,first);err!=nil{return err};first=false
  if filepath.Dir(current)==current{break}
 }
 return nil
}
func checkWindowsACL(path string, destination bool) error {
 u,err:=user.Current();if err!=nil{return err}
 getInfo:=advapi.NewProc("GetNamedSecurityInfoW")
 convertSID:=advapi.NewProc("ConvertStringSidToSidW")
 equalSID:=advapi.NewProc("EqualSid")
 getACE:=advapi.NewProc("GetAce")
 name,err:=syscall.UTF16PtrFromString(path);if err!=nil{return err}
 var owner,dacl,descriptor uintptr
 result,_,_:=getInfo.Call(uintptr(unsafe.Pointer(name)),1,5,uintptr(unsafe.Pointer(&owner)),0,uintptr(unsafe.Pointer(&dacl)),0,uintptr(unsafe.Pointer(&descriptor)))
 if result!=0{return syscall.Errno(result)};defer localFree.Call(descriptor)
 if owner==0 || dacl==0{return errors.New("directory has no safe owner/DACL")}
 var allowed []uintptr
 defer func(){for _,sid:=range allowed{localFree.Call(sid)}}()
 for _,value:=range []string{u.Uid,"S-1-5-18","S-1-5-32-544"}{
  text,err:=syscall.UTF16PtrFromString(value);if err!=nil{return err};var sid uintptr
  ok,_,e:=convertSID.Call(uintptr(unsafe.Pointer(text)),uintptr(unsafe.Pointer(&sid)));if ok==0{return e};allowed=append(allowed,sid)
 }
 trustedOwner:=false;for _,sid:=range allowed{same,_,_:=equalSID.Call(owner,sid);if same!=0{trustedOwner=true;break}};if !trustedOwner{return errors.New("directory owner is not a trusted account")}
 type aclHeader struct{Revision uint8;Sbz1 uint8;Size uint16;Count uint16;Sbz2 uint16}
 count:=(*aclHeader)(unsafe.Pointer(dacl)).Count
 for i:=uint16(0);i<count;i++{
  var ace uintptr;ok,_,e:=getACE.Call(dacl,uintptr(i),uintptr(unsafe.Pointer(&ace)));if ok==0{return e}
  kind:=*(*uint8)(unsafe.Pointer(ace));flags:=*(*uint8)(unsafe.Pointer(ace+1))
  if flags&8!=0 || kind==1{continue} // inherit-only or deny ACE
  if kind!=0{return errors.New("unsupported destination ACL; use a private directory")}
  writeMask:=uint32(0x500d0040);if destination{writeMask=0x500d0156}
  mask:=*(*uint32)(unsafe.Pointer(ace+4));if mask&writeMask==0{continue}
  permitted:=false;for _,sid:=range allowed{same,_,_:=equalSID.Call(ace+8,sid);if same!=0{permitted=true;break}}
  if !permitted{return errors.New("destination directory is writable by another account")}
 }
 return nil
}
