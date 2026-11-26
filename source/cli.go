package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Transport is always explicitly chosen. The parser never falls back to a
// different transport, even when the selected transport is unavailable.
func transferArgs(args []string) ([]string, string, int64, int, error) {
	via := ""
	chunk := activeSettings.Chunk
	parallel := activeSettings.Parallel
	if chunk == 0 {
		chunk = 1024 * 1024
	}
	if parallel == 0 {
		parallel = 1
	}
	pos := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--via", "--chunk", "--parallel":
			key := args[i]
			i++
			if i >= len(args) {
				return nil, "", 0, 0, fmt.Errorf("%s requires a value", key)
			}
			switch key {
			case "--via":
				via = strings.ToLower(args[i])
			case "--chunk":
				n, e := parseChunk(args[i])
				if e != nil {
					return nil, "", 0, 0, e
				}
				chunk = n
			case "--parallel":
				n, e := strconv.Atoi(args[i])
				if e != nil || n < 1 || n > 8 {
					return nil, "", 0, 0, errors.New("parallel must be 1..8")
				}
				parallel = n
			}
		default:
			if strings.HasPrefix(args[i], "-") {
				return nil, "", 0, 0, fmt.Errorf("unsupported option %s", args[i])
			}
			pos = append(pos, args[i])
		}
	}
	if via != "https" && via != "sftp" {
		return nil, "", 0, 0, errors.New("choose --via https|sftp (no automatic fallback)")
	}
	return pos, via, chunk, parallel, nil
}
func dispatchSend(args []string) error {
	filtered, reset, e := extractNetworkArgs(args)
	if e != nil {
		return e
	}
	defer reset()
	pos, via, chunk, parallel, e := transferArgs(filtered)
	if e != nil {
		return e
	}
	if len(pos) != 2 {
		return errors.New("usage: xer send FILE DESTINATION --via https|sftp")
	}
	if via=="https" && activeSFTPPort!=0 {return errors.New("HTTPS requires HOST:PORT; --port is SFTP-only")}
	if via == "https" {
		return sendFileWithOptions(pos[0], pos[1], chunk, parallel)
	}
	if hasChunkOptions(filtered) {
		return errors.New("chunk/parallel only supported by HTTPS")
	}
	return sftpSend(pos[0], pos[1], activeSFTPPort)
}
func dispatchGet(args []string) error {
	filtered, reset, e := extractNetworkArgs(args)
	if e != nil {
		return e
	}
	defer reset()
	pos, via, _, _, e := transferArgs(filtered)
	if e != nil {
		return e
	}
	if len(pos) < 1 || len(pos) > 2 {
		return errors.New("usage: xer get SOURCE [DESTINATION] --via https|sftp")
	}
	dest := ""
	if len(pos) == 2 {
		dest = pos[1]
	}
	if hasChunkOptions(filtered) {
		return errors.New("chunk/parallel only supported on HTTPS uploads")
	}
	if via=="https" && activeSFTPPort!=0 {return errors.New("HTTPS requires HOST:PORT; --port is SFTP-only")}
	if via == "https" {
		return getFile(pos[0], dest)
	}
	return sftpGet(pos[0], dest, activeSFTPPort)
}

func hasChunkOptions(args []string)bool{for _,arg:=range args{if arg=="--chunk" || arg=="--parallel"{return true}};return false}
