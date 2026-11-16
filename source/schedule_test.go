package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestScheduleFormats(t *testing.T) {
	s, tm := systemdUnits("/home/user/xer file%name")
	if !strings.Contains(s, `"/home/user/xer file%%name" auto tick`) || !strings.Contains(tm, "OnCalendar=") {
		t.Fatalf("invalid systemd schedule: %s %s", s, tm)
	}
	plist := launchAgent("/Applications/XER & tools/xer")
	var v any
	if e := xml.Unmarshal([]byte(plist), &v); e != nil {
		t.Fatalf("invalid plist XML: %v", e)
	}
	if !strings.Contains(plist, "&amp;") {
		t.Fatal("XML executable path not escaped")
	}
}
