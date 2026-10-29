// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Test-only encryption isolates file transactions from OS backend availability.
type testEncryption struct {
	cipher.AEAD
	fail bool
}

func (testEncryption) Name() string                { return "test-only" }
func (testEncryption) Check(context.Context) error { return nil }
func (c testEncryption) Encrypt(_ context.Context, data []byte) ([]byte, error) {
	if c.fail {
		return nil, ErrUnavailable
	}
	nonce := make([]byte, c.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.Seal(nonce, nonce, data, nil), nil
}
func (c testEncryption) Decrypt(_ context.Context, data []byte) ([]byte, error) {
	if len(data) < c.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	return c.Open(nil, data[:c.NonceSize()], data[c.NonceSize():], nil)
}
func fixtureStore(t *testing.T) *Store {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &Store{path: filepath.Join(t.TempDir(), "private", "credentials.enc"), crypto: testEncryption{AEAD: aead}}
}

func exerciseStore(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	record := Record{TunnelID: "tunnel_local-test", APIKey: "test-secret-never-print", OrganizationID: "org-local", BaseURL: "https://api.openai.com"}
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(record.APIKey)) || bytes.Contains(data, []byte(record.TunnelID)) {
		t.Fatal("plaintext in credential file")
	}
	loaded, err := store.Load(ctx)
	if err != nil || loaded.APIKey != record.APIKey || loaded.TunnelID != record.TunnelID || loaded.CreatedAt == "" {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if err := store.Create(ctx, record); !errors.Is(err, ErrExists) {
		t.Fatalf("create overwrote record: %v", err)
	}
	if err := store.Update(ctx, func(r *Record) error { r.APIKey = "new-secret-never-print"; return nil }); err != nil {
		t.Fatal(err)
	}
	updated, err := store.Load(ctx)
	if err != nil || updated.APIKey != "new-secret-never-print" || updated.OrganizationID != record.OrganizationID || updated.CreatedAt != loaded.CreatedAt {
		t.Fatalf("patch lost data: %v", err)
	}
	before, _ := os.ReadFile(store.Path())
	if err := store.Update(ctx, func(r *Record) error { r.APIKey = ""; return nil }); err == nil {
		t.Fatal("accepted empty API key")
	}
	after, _ := os.ReadFile(store.Path())
	if !bytes.Equal(before, after) {
		t.Fatal("invalid update damaged old credential")
	}
	entries, err := os.ReadDir(filepath.Dir(store.Path()))
	if err != nil || len(entries) != 1 || entries[0].Name() != "credentials.enc" {
		t.Fatal("unexpected temporary or lock file left behind")
	}
	if err := store.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx); err != nil {
		t.Fatal("delete is not idempotent")
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted record loaded: %v", err)
	}
	if err := store.Update(ctx, func(*Record) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update created missing record: %v", err)
	}
}

func TestStoreTransactions(t *testing.T) { exerciseStore(t, fixtureStore(t)) }

func TestFailedEncryptionRetainsOldFile(t *testing.T) {
	s := fixtureStore(t)
	ctx := context.Background()
	if err := s.Create(ctx, Record{TunnelID: "tunnel_test", APIKey: "secret-before-failure"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.path)
	c := s.crypto.(testEncryption)
	c.fail = true
	s.crypto = c
	if err := s.Update(ctx, func(r *Record) error { r.APIKey = "new-key"; return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.path)
	if !bytes.Equal(before, after) {
		t.Fatal("backend failure damaged credentials")
	}
}

func TestConcurrentUpdatesDoNotLoseChanges(t *testing.T) {
	s := fixtureStore(t)
	ctx := context.Background()
	if err := s.Create(ctx, Record{TunnelID: "tunnel_test", APIKey: "secret", OrganizationID: "0"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := s.Update(ctx, func(r *Record) error {
				n, _ := strconv.Atoi(r.OrganizationID)
				r.OrganizationID = strconv.Itoa(n + 1)
				return nil
			}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	r, err := s.Load(ctx)
	if err != nil || r.OrganizationID != "8" {
		t.Fatal("concurrent changes lost", err)
	}
}

func TestTamperedOversizedAndLinkedFilesRejected(t *testing.T) {
	s := fixtureStore(t)
	ctx := context.Background()
	if err := s.Create(ctx, Record{TunnelID: "tunnel_test", APIKey: "private-secret"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(s.path)
	data[len(data)-1] ^= 1
	if err := os.WriteFile(s.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); err == nil {
		t.Fatal("tampered record accepted")
	}
	if err := os.WriteFile(s.path, bytes.Repeat([]byte{'x'}, maxFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); err == nil {
		t.Fatal("oversized record accepted")
	}
	link := filepath.Join(filepath.Dir(s.path), "second-name")
	if err := os.Link(s.path, link); err != nil {
		t.Skip("hard links unavailable")
	}
	if _, err := s.Load(ctx); err == nil {
		t.Fatal("hard-linked credentials accepted")
	}
}

func TestResolvePathOverridesWithoutCreating(t *testing.T) {
	root := t.TempDir()
	env := map[string]string{"HOST_MONITOR_CREDENTIALS_FILE": filepath.Join(root, "env", "credentials.enc")}
	getenv := func(k string) string { return env[k] }
	path, err := ResolvePath("", getenv)
	if err != nil || path != env["HOST_MONITOR_CREDENTIALS_FILE"] {
		t.Fatal("env override", err)
	}
	explicit := filepath.Join(root, "cli", "credentials.enc")
	path, err = ResolvePath(explicit, getenv)
	if err != nil || path != explicit {
		t.Fatal("CLI override", err)
	}
	path, err = ResolvePath("relative.enc", getenv)
	want, _ := filepath.Abs("relative.enc")
	if err != nil || path != want {
		t.Fatal("relative path", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("path resolution created files")
	}
}

func TestSecretValidationAndFormatting(t *testing.T) {
	secret := "do-not-print-secret"
	r := Record{TunnelID: "tunnel_test", APIKey: secret}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, r), secret) {
			t.Fatal("formatting leaked secret")
		}
	}
	for _, key := range []string{"", "\nsecret", "secret\x00", string([]byte{0xff})} {
		r.APIKey = key
		if err := r.Validate(); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
}
