// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxDefaultCredentialsPaths(t *testing.T) {
	for _, tc := range []struct{ xdg, home, want string }{
		{"/custom/data", "/home/test", "/custom/data/host-monitor/credentials.enc"},
		{"", "/home/test", "/home/test/.local/share/host-monitor/credentials.enc"},
		{"relative", "/home/test", "/home/test/.local/share/host-monitor/credentials.enc"},
	} {
		got, err := ResolvePath("", func(k string) string {
			if k == "XDG_DATA_HOME" {
				return tc.xdg
			}
			if k == "HOME" {
				return tc.home
			}
			return ""
		})
		if err != nil || got != tc.want {
			t.Fatalf("path=%s err=%v", got, err)
		}
	}
}

func TestLinuxPermissionsAndSymlinks(t *testing.T) {
	s := fixtureStore(t)
	ctx := context.Background()
	if err := s.Create(ctx, Record{TunnelID: "tunnel_test", APIKey: "secret"}); err != nil {
		t.Fatal(err)
	}
	file, _ := os.Stat(s.path)
	dir, _ := os.Stat(filepath.Dir(s.path))
	if file.Mode().Perm() != 0600 || dir.Mode().Perm() != 0700 {
		t.Fatal("incorrect file/directory permissions")
	}
	if err := os.Chmod(s.path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); err == nil {
		t.Fatal("publicly readable credentials accepted")
	}
	os.Chmod(s.path, 0600)
	link := filepath.Join(filepath.Dir(s.path), "link.enc")
	if err := os.Symlink(s.path, link); err != nil {
		t.Fatal(err)
	}
	s.path = link
	if _, err := s.Load(ctx); err == nil {
		t.Fatal("symlink followed")
	}
	if err := s.Delete(ctx); err == nil {
		t.Fatal("symlink deleted through credential command")
	}
}

func TestNativeSystemdRoundtripWhenAvailable(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "private", "credentials.enc"))
	ctx := context.Background()
	if err := s.Check(ctx); err != nil {
		t.Skip("supported systemd-creds not available")
	}
	// Do not initialize the host key while running tests on an unprovisioned OS.
	if _, err := os.Stat("/var/lib/systemd/credential.secret"); err != nil {
		t.Skip("host credential key is not readable; native test requires a provisioned test host")
	}
	exerciseStore(t, s)
}
