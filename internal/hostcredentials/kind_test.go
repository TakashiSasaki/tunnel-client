// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSeparateRuntimeAndAdminLifecycle(t *testing.T) {
	runtime := fixtureStore(t)
	admin := &Store{path: filepath.Join(filepath.Dir(runtime.path), "credentials.admin.enc"), crypto: runtime.crypto, kind: Admin}
	ctx := context.Background()
	if err := runtime.Create(ctx, Record{APIKey: "runtime-test-secret", TunnelID: "tunnel_test"}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, Record{Kind: Admin, APIKey: "admin-test-secret"}); err != nil {
		t.Fatal(err)
	}
	adminBefore, _ := os.ReadFile(admin.path)
	if err := runtime.Update(ctx, func(r *Record) error { r.APIKey = "runtime-updated"; return nil }); err != nil {
		t.Fatal(err)
	}
	adminAfter, _ := os.ReadFile(admin.path)
	if !bytes.Equal(adminBefore, adminAfter) {
		t.Fatal("runtime update changed admin file")
	}
	runtimeBefore, _ := os.ReadFile(runtime.path)
	if err := admin.Update(ctx, func(r *Record) error { r.APIKey = "admin-updated"; return nil }); err != nil {
		t.Fatal(err)
	}
	runtimeAfter, _ := os.ReadFile(runtime.path)
	if !bytes.Equal(runtimeBefore, runtimeAfter) {
		t.Fatal("admin update changed runtime file")
	}
	if err := admin.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := runtime.Load(ctx); err != nil || r.APIKey != "runtime-updated" {
		t.Fatal("admin deletion affected runtime", err)
	}
	if err := admin.Create(ctx, Record{Kind: Admin, APIKey: "admin-recreated"}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := admin.Load(ctx); err != nil || r.APIKey != "admin-recreated" {
		t.Fatal("runtime deletion affected admin", err)
	}
}

type countingEncryption struct {
	encryption
	decrypts int
}

func (c *countingEncryption) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	c.decrypts++
	return c.encryption.Decrypt(ctx, data)
}

func TestWrongKindCannotReadUpdateOrDelete(t *testing.T) {
	for _, kind := range []Kind{Runtime, Admin} {
		t.Run(string(kind), func(t *testing.T) {
			s := fixtureStore(t)
			s.kind = kind
			r := Record{Kind: kind, APIKey: "secret"}
			other := Runtime
			if kind == Runtime {
				r.TunnelID = "tunnel_test"
				other = Admin
			}
			ctx := context.Background()
			if err := s.Create(ctx, r); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(s.path)
			counter := &countingEncryption{encryption: s.crypto}
			wrong := &Store{path: s.path, crypto: counter, kind: other}
			if _, err := wrong.Load(ctx); !errors.Is(err, ErrKind) {
				t.Fatal("wrong-kind load", err)
			}
			if err := wrong.Update(ctx, func(*Record) error { t.Error("patch invoked for wrong type"); return nil }); !errors.Is(err, ErrKind) {
				t.Fatal("wrong-kind update", err)
			}
			if err := wrong.Delete(ctx); !errors.Is(err, ErrKind) {
				t.Fatal("wrong-kind delete", err)
			}
			if counter.decrypts != 0 {
				t.Fatal("wrong-kind ciphertext decrypted")
			}
			after, _ := os.ReadFile(s.path)
			if !bytes.Equal(before, after) {
				t.Fatal("wrong type changed file")
			}
		})
	}
}

func TestLegacyRuntimeRecordAndAuthenticatedKind(t *testing.T) {
	s := fixtureStore(t)
	ctx := context.Background()
	legacy := Record{Version: 1, TunnelID: "tunnel_legacy", APIKey: "legacy-secret", CreatedAt: "2026-01-01T00:00:00Z"}
	plain, _ := json.Marshal(legacy)
	if bytes.Contains(plain, []byte(`"type"`)) {
		t.Fatal("legacy fixture has a type field")
	}
	ciphertext, err := s.crypto.Encrypt(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := makePrivateDirs(filepath.Dir(s.path)); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(s.path, append([]byte(s.prefix()), ciphertext...), true); err != nil {
		t.Fatal(err)
	}
	r, err := s.Load(ctx)
	if err != nil || r.EffectiveKind() != Runtime || r.APIKey != "legacy-secret" {
		t.Fatal("legacy record rejected", err)
	}
	if err := s.Update(ctx, func(r *Record) error { r.APIKey = "updated-secret"; return nil }); err != nil {
		t.Fatal(err)
	}
	r, err = s.Load(ctx)
	if err != nil || r.Kind != Runtime || r.CreatedAt != legacy.CreatedAt {
		t.Fatal("legacy update failed", err)
	}
	// Re-labeling only a public header cannot change the authenticated type.
	data, _ := os.ReadFile(s.path)
	admin := &Store{path: s.path, crypto: s.crypto, kind: Admin}
	data = append([]byte(admin.prefix()), data[len(s.prefix()):]...)
	if err := os.WriteFile(s.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Load(ctx); !errors.Is(err, ErrKind) {
		t.Fatal("authenticated type mismatch accepted", err)
	}
}

func TestAdminPathSelectionAndValidation(t *testing.T) {
	root := t.TempDir()
	defaultEnv := func(key string) string {
		if key == "HOME" {
			return root
		}
		return ""
	}
	runtimeDefault, err := ResolvePathFor(Runtime, "", defaultEnv)
	if err != nil {
		t.Fatal(err)
	}
	adminDefault, err := ResolvePathFor(Admin, "", defaultEnv)
	if err != nil || adminDefault != filepath.Join(filepath.Dir(runtimeDefault), "credentials.admin.enc") {
		t.Fatal("wrong default admin path", err)
	}
	env := map[string]string{"HOST_MONITOR_CREDENTIALS_FILE": filepath.Join(root, "runtime.enc"), "HOST_MONITOR_ADMIN_CREDENTIALS_FILE": filepath.Join(root, "admin.enc")}
	getenv := func(k string) string { return env[k] }
	for _, kind := range []Kind{Runtime, Admin} {
		path, err := ResolvePathFor(kind, "", getenv)
		want := env["HOST_MONITOR_CREDENTIALS_FILE"]
		if kind == Admin {
			want = env["HOST_MONITOR_ADMIN_CREDENTIALS_FILE"]
		}
		if err != nil || path != want {
			t.Fatal("type-specific env ignored", err)
		}
		explicit := filepath.Join(root, "exact-name.enc")
		if path, err := ResolvePathFor(kind, explicit, getenv); err != nil || path != explicit {
			t.Fatal("explicit name rewritten", err)
		}
	}
	if (Record{Kind: Admin, APIKey: "secret"}).Validate() != nil {
		t.Fatal("admin required a tunnel ID")
	}
	if (Record{Kind: Admin, APIKey: "secret", TunnelID: "tunnel_test"}).Validate() == nil {
		t.Fatal("admin accepted tunnel ID")
	}
	if (Record{Kind: Runtime, APIKey: "secret"}).Validate() == nil {
		t.Fatal("runtime accepted missing tunnel ID")
	}
}
