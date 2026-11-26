package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
)

var errStateBusy = errors.New("XER state is in use by another operation")

// State and staging directories must belong to this account. Existing unsafe
// directories are rejected, not silently made private after data was exposed.
func privateDir(path string) error {
 if err := os.MkdirAll(path, 0700); err != nil { return err }
 st, err := os.Lstat(path)
 if err != nil { return err }
 if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 { return errors.New("state directory must not be a link") }
 if err = validateDirectory(st, true); err != nil { return fmt.Errorf("unsafe state directory %s: %w", path, err) }
 return protectPath(path, true)
}

func trustedDirectory(path string) error {
 st, err := os.Lstat(path)
 if err != nil { return err }
 if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 { return errors.New("destination directory must not be a link") }
 if err=validateDirectory(st,false);err!=nil{return err};return checkDestinationACL(path)
}

func readPrivate(path string, limit int64) ([]byte, error) {
 f, err := openPrivate(path, os.O_RDONLY)
 if err != nil { return nil, err }
 defer f.Close()
 b, err := io.ReadAll(io.LimitReader(f, limit+1))
 if err != nil { return nil, err }
 if int64(len(b)) > limit { return nil, errors.New("state file exceeds size limit") }
 return b, nil
}

func readPrivateJSON(path string, dst any, limit int64) error {
 b, err := readPrivate(path, limit)
 if err != nil { return err }
 return json.Unmarshal(b, dst)
}

func writeExclusive(path string, data []byte) error {
 f, err := openPrivate(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
 if err != nil { return err }
 ok := false
 defer func(){ f.Close(); if !ok { _ = os.Remove(path) } }()
 if _, err = f.Write(data); err != nil { return err }
 if err = f.Sync(); err != nil { return err }
 if err = f.Close(); err != nil { return err }
 if err = syncDirectory(filepath.Dir(path)); err != nil { return err }
 ok = true
 return nil
}

func openDownloadSource(rootPath, name string) (*os.File, error) {
 root, err := os.OpenRoot(rootPath)
 if err != nil { return nil, err }
 defer root.Close()
 // Root confines traversal, including a symlink swapped during OpenFile.
 before, err := root.Lstat(name)
 if err != nil || !before.Mode().IsRegular() { return nil, errors.New("not a regular file") }
 f, err := root.OpenFile(name, os.O_RDONLY|safeReadFlags(), 0)
 if err != nil { return nil, err }
 after, err := f.Stat()
 if err != nil || !os.SameFile(before, after) { f.Close(); return nil, errors.New("file changed while opening") }
 if err = validateOpenFile(f, false); err != nil { f.Close(); return nil, err }
 return f, nil
}

// The lock is held by the kernel and released on process exit. The lock file
// remains, so an interrupted process never leaves a permanent O_EXCL lock.
type fileLock struct { f *os.File }
func acquireLock(path string) (*fileLock, error) {
 if err := privateDir(filepath.Dir(path)); err != nil { return nil, err }
 f, err := openPrivate(path, os.O_CREATE|os.O_RDWR)
 if err != nil { return nil, err }
 if err = lockHandle(f); err != nil { f.Close(); return nil, err }
 return &fileLock{f:f}, nil
}
func (l *fileLock) Close() error { return l.f.Close() }

func readBoundedRegular(path string,limit int64)([]byte,error){
 f,err:=os.OpenFile(path,os.O_RDONLY|safeReadFlags(),0);if err!=nil{return nil,err};defer f.Close()
 st,err:=f.Stat();if err!=nil{return nil,err};if !st.Mode().IsRegular(){return nil,errors.New("configuration must be a regular file")}
 b,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err};if int64(len(b))>limit{return nil,errors.New("configuration exceeds size limit")};return b,nil
}
