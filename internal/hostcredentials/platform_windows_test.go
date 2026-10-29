// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNativeDPAPIStore(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "private", "credentials.enc"))
	exerciseStore(t, store)
}

func TestNativeDPAPIBindingAndACL(t *testing.T) {
	ctx := context.Background()
	s := New(filepath.Join(t.TempDir(), "private", "credentials.enc"))
	if err := s.Create(ctx, Record{TunnelID: "tunnel_test", APIKey: "secret"}); err != nil {
		t.Fatal(err)
	}
	f, err := openPrivateRead(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, _ := sd.Control()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("credential ACL inherits parent permissions")
	}
	sid, _ := currentSID()
	sddl := sd.String()
	if !strings.Contains(sddl, sid) || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;AU)") {
		t.Fatalf("unexpected file ACL: %s", sddl)
	}
	// The encrypted blob requires the application context (entropy) as well as
	// the user. Plain DPAPI without this context cannot decrypt it.
	data, _ := os.ReadFile(s.Path())
	data = data[len(fileHeader)+len(s.Backend())+1:]
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err == nil {
		windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
		t.Fatal("credential context binding missing")
	}
}

func TestWindowsDefaultCredentialsPath(t *testing.T) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolvePath("", func(string) string { return "" })
	if err != nil || got != filepath.Join(base, "TakashiSasaki", "HostMonitor", "credentials.enc") {
		t.Fatal("default path", err)
	}
}
