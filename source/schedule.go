package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const timerName = "xer-auto"

func scheduleAction(action string) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	if strings.ContainsAny(exe, "\r\n\x00") {
		return errors.New("unsafe executable path")
	}
	switch runtime.GOOS {
	case "linux":
		return scheduleLinux(action, exe)
	case "windows":
		return scheduleWindows(action, exe)
	case "darwin":
		return scheduleMac(action, exe)
	default:
		return errors.New("native scheduling is supported on Windows, Linux and macOS")
	}
}
func systemdArg(path string) string {
	// Systemd specifier expansion is disabled by doubling %.
	path = strings.ReplaceAll(path, "%", "%%")
	path = strings.ReplaceAll(path,"$","$$")
	path = strings.ReplaceAll(path, "\\", "\\\\")
	path = strings.ReplaceAll(path, "\"", "\\\"")
	return "\"" + path + "\""
}
func systemdUnits(exe string) (string, string) {
	service := "[Unit]\nDescription=XER scheduled file transfers\n[Service]\nType=oneshot\nExecStart=" + systemdArg(exe) + " auto tick\n"
	timer := "[Unit]\nDescription=Run XER automation every minute\n[Timer]\nOnCalendar=*-*-* *:*:00\nPersistent=true\nUnit=xer-auto.service\n[Install]\nWantedBy=timers.target\n"
	return service, timer
}
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, e, strings.TrimSpace(string(output)))
	}
	return nil
}
func scheduleLinux(action, exe string) error {
	d, e := os.UserConfigDir()
	if e != nil {
		return e
	}
	// On Linux UserConfigDir is typically $XDG_CONFIG_HOME; systemd units live
	// under ~/.config/systemd/user regardless of XDG_CONFIG_HOME.
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	_ = d
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	servicePath := filepath.Join(unitDir, "xer-auto.service")
	timerPath := filepath.Join(unitDir, "xer-auto.timer")
	switch action {
	case "install":
		if e = os.MkdirAll(unitDir, 0700); e != nil {
			return e
		}
		service, timer := systemdUnits(exe)
		if e = os.WriteFile(servicePath, []byte(service), 0600); e != nil {
			return e
		}
		if e = os.WriteFile(timerPath, []byte(timer), 0600); e != nil {
			return e
		}
		if e = runCmd("systemctl", "--user", "daemon-reload"); e != nil {
			return e
		}
		return runCmd("systemctl", "--user", "enable", "--now", "xer-auto.timer")
	case "uninstall":
		_ = runCmd("systemctl", "--user", "disable", "--now", "xer-auto.timer")
		if e = os.Remove(servicePath); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e = os.Remove(timerPath); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return runCmd("systemctl", "--user", "daemon-reload")
	}
	return errors.New("unsupported schedule action")
}
func scheduleWindows(action, exe string) error {
	switch action {
	case "install":
		if strings.ContainsAny(exe,"%\"\r\n\x00"){return errors.New("unsafe executable path for Windows scheduler")}
		quoted := "\"" + exe + "\" auto tick"
		return runCmd("schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", "1", "/TN", "XER-Auto", "/TR", quoted)
	case "uninstall":
		return runCmd("schtasks", "/Delete", "/F", "/TN", "XER-Auto")
	}
	return errors.New("unsupported schedule action")
}
func xmlEscape(s string) string {
	var out bytes.Buffer
	_ = xml.EscapeText(&out, []byte(s))
	return out.String()
}
func launchAgent(exe string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		"<plist version=\"1.0\"><dict>" +
		"<key>Label</key><string>com.0xallow.xer.auto</string>" +
		"<key>ProgramArguments</key><array><string>" + xmlEscape(exe) + "</string><string>auto</string><string>tick</string></array>" +
		"<key>StartInterval</key><integer>60</integer>" +
		"<key>RunAtLoad</key><true/>" +
		"</dict></plist>\n"
}
func scheduleMac(action, exe string) error {
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	d := filepath.Join(home, "Library", "LaunchAgents")
	path := filepath.Join(d, "com.0xallow.xer.auto.plist")
	target := "gui/" + strconv.Itoa(os.Getuid())
	switch action {
	case "install":
		if e = os.MkdirAll(d, 0700); e != nil {
			return e
		}
		if e = os.WriteFile(path, []byte(launchAgent(exe)), 0600); e != nil {
			return e
		}
		return runCmd("launchctl", "bootstrap", target, path)
	case "uninstall":
		_ = runCmd("launchctl", "bootout", target+"/com.0xallow.xer.auto")
		if e = os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return nil
	}
	return errors.New("unsupported schedule action")
}
