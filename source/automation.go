package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Intentionally constrained YAML subset: five scalar keys, no YAML tags, anchors or nesting.
type Job struct{ Name, From, To, Via, Every, At string }

func parseJob(data []byte) (Job, error) {
	var j Job
	if len(data) > 64*1024 {
		return j, errors.New("job file too large")
	}
	values := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, "\t") || strings.HasPrefix(line, "-") {
			return j, errors.New("only flat key: value YAML is supported")
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return j, errors.New("expected key: value")
		}
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if k != "name" && k != "from" && k != "to" && k != "every" && k != "at" && k != "via" {
			return j, fmt.Errorf("unknown YAML key %q", k)
		}
		if _, ok := values[k]; ok {
			return j, fmt.Errorf("duplicate YAML key %q", k)
		}
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if v == "" || strings.ContainsAny(v, "\r\n\x00") || strings.ContainsAny(v, "#{}[]&*!|><`") {
			return j, fmt.Errorf("invalid scalar value for %s", k)
		}
		values[k] = v
	}
	if err := sc.Err(); err != nil {
		return j, err
	}
	j = Job{values["name"], values["from"], values["to"], values["via"], values["every"], values["at"]}
	if !endpointName.MatchString(j.Name) || j.From == "" || j.To == "" {
		return j, errors.New("job requires valid name, from and to")
	}
	if j.Via == "" {
		return j, errors.New("automation requires explicit via: protocol")
	}
	if j.Every == "" {
		j.Every = "manual"
	}
	if j.Every != "manual" && j.Every != "daily" && j.Every != "hourly" {
		return j, errors.New("every must be manual, hourly or daily")
	}
	if j.Every == "daily" {
		if _, err := time.Parse("15:04", j.At); err != nil {
			return j, errors.New("daily job needs at: HH:MM")
		}
	} else if j.At != "" {
		return j, errors.New("at is supported only for daily jobs")
	}
	return j, nil
}
func jobFolder() (string, error) { d, e := configDir(); return filepath.Join(d, "jobs"), e }
func loadJob(name string) (Job, error) {
	if !endpointName.MatchString(name) {
		return Job{}, errors.New("invalid job name")
	}
	dir, e := jobFolder()
	if e != nil {
		return Job{}, e
	}
	b, e := os.ReadFile(filepath.Join(dir, name+".yaml"))
	if e != nil {
		return Job{}, e
	}
	return parseJob(b)
}
func runJob(j Job) error {
	if j.From == "~" || strings.HasPrefix(j.From, "~/") {
		h, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		j.From = filepath.Join(h, strings.TrimPrefix(j.From, "~/"))
	}
	switch j.Via {
	case "https":
		// Automated transfers must have a pre-paired identity; never prompt in a scheduled job.
		profiles, e := loadProfiles()
		if e != nil {
			return e
		}
		if _, ok := profiles.Servers[j.To]; !ok {
			return errors.New("pair with receiver interactively before scheduling this job")
		}
		return sendFileWithOptions(j.From, j.To, activeSettings.Chunk, activeSettings.Parallel)
	case "sftp":
		return sftpSend(j.From, j.To, 22)
	default:
		return errors.New("automation supports only https or sftp")
	}
}
func automation(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xer auto add FILE.yaml | run NAME | list | tick")
	}
	dir, e := jobFolder()
	if e != nil {
		return e
	}
	switch args[0] {
	case "add":
		if len(args) != 2 {
			return errors.New("usage: xer auto add FILE.yaml")
		}
		b, e := os.ReadFile(args[1])
		if e != nil {
			return e
		}
		j, e := parseJob(b)
		if e != nil {
			return e
		}
		if e = os.MkdirAll(dir, 0700); e != nil {
			return e
		}
		dest := filepath.Join(dir, j.Name+".yaml")
		f, e := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Println("Saved automation:", j.Name)
		return nil
	case "list":
		if len(args) != 1 {
			return errors.New("usage: xer auto list")
		}
		items, e := os.ReadDir(dir)
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		for _, v := range items {
			if strings.HasSuffix(v.Name(), ".yaml") {
				fmt.Println(strings.TrimSuffix(v.Name(), ".yaml"))
			}
		}
		return nil
	case "install", "uninstall":
		if len(args) != 1 {
			return errors.New("usage: xer auto install|uninstall")
		}
		return scheduleAction(args[0])
	case "remove":
		if len(args) != 2 || !endpointName.MatchString(args[1]) {
			return errors.New("usage: xer auto remove NAME")
		}
		return os.Remove(filepath.Join(dir, args[1]+".yaml"))
	case "run":
		if len(args) != 2 {
			return errors.New("usage: xer auto run NAME")
		}
		j, e := loadJob(args[1])
		if e != nil {
			return e
		}
		return runJob(j)
	case "tick":
		// Call from the OS scheduler every minute. Timestamp is local time; job lock state
		// prevents duplicate execution of same slot after restarts.
		if len(args) != 1 {
			return errors.New("usage: xer auto tick")
		}
		items, e := os.ReadDir(dir)
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		now := time.Now()
		// Expire old idempotency locks to avoid unbounded metadata growth.
		for _, entry := range items {
			if strings.HasSuffix(entry.Name(), ".lock") {
				info, err := entry.Info()
				if err == nil && now.Sub(info.ModTime()) > 48*time.Hour {
					_ = os.Remove(filepath.Join(dir, entry.Name()))
				}
			}
		}
		for _, entry := range items {
			if !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}
			name := strings.TrimSuffix(entry.Name(), ".yaml")
			j, e := loadJob(name)
			if e != nil {
				return e
			}
			due := j.Every == "hourly" && now.Minute() == 0 || j.Every == "daily" && now.Format("15:04") == j.At
			if !due {
				continue
			}
			key := now.Format("200601021504")
			lock := filepath.Join(dir, name+"."+key+".lock")
			f, e := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if errors.Is(e, os.ErrExist) {
				continue
			}
			if e != nil {
				return e
			}
			f.Close()
			if e = runJob(j); e != nil {
				return fmt.Errorf("job %s: %w", name, e)
			}
		}
		return nil
	default:
		return errors.New("unknown auto command")
	}
}
