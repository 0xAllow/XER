//go:build windows

package main
import("errors";"os/user";"syscall";"unsafe")
func secureKeyFile(path string)error{
 u,err:=user.Current();if err!=nil{return err}
 sddl,err:=syscall.UTF16PtrFromString("D:P(A;;FA;;;"+u.Uid+")(A;;FA;;;SY)");if err!=nil{return err}
 adv:=syscall.NewLazyDLL("advapi32.dll");var descriptor uintptr
 ok,_,err:=adv.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW").Call(uintptr(unsafe.Pointer(sddl)),1,uintptr(unsafe.Pointer(&descriptor)),0);if ok==0{return err}
 defer syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree").Call(descriptor)
 name,err:=syscall.UTF16PtrFromString(path);if err!=nil{return err}
 var present,defaulted uint32;var acl uintptr
 ok,_,err=adv.NewProc("GetSecurityDescriptorDacl").Call(descriptor,uintptr(unsafe.Pointer(&present)),uintptr(unsafe.Pointer(&acl)),uintptr(unsafe.Pointer(&defaulted)));if ok==0{return err};if present==0 || acl==0{return errors.New("missing private DACL")}
 result,_,_:=adv.NewProc("SetNamedSecurityInfoW").Call(uintptr(unsafe.Pointer(name)),1,uintptr(0x80000004),0,0,acl,0);if result!=0{return syscall.Errno(result)};return nil
}
