//go:build !linux && !darwin && !windows

package main

import ("errors"; "os")
func validateDirectory(os.FileInfo, bool) error { return errors.New("unsupported OS") }
func protectPath(string, bool) error { return errors.New("unsupported OS") }
func safeReadFlags() int { return 0 }
func validateOpenFile(*os.File, bool) error { return errors.New("unsupported OS") }
func openPrivate(string, int) (*os.File,error) { return nil,errors.New("unsupported OS") }
func lockHandle(*os.File) error { return errors.New("unsupported OS") }
func syncDirectory(string) error { return errors.New("unsupported OS") }

func checkDestinationACL(_ string) error { return nil }
