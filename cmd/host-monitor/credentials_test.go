// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openai/tunnel-client/internal/hostcredentials"
)

type memoryCredentialStore struct {
	path     string
	record   *hostcredentials.Record
	writes   int
	checkErr error
}

func (s *memoryCredentialStore) Path() string                { return s.path }
func (*memoryCredentialStore) Backend() string               { return "test-only" }
func (s *memoryCredentialStore) Check(context.Context) error { return s.checkErr }
func (s *memoryCredentialStore) Exists() (bool, error)       { return s.record != nil, nil }
func (s *memoryCredentialStore) Load(context.Context) (hostcredentials.Record, error) {
	if s.record == nil {
		return hostcredentials.Record{}, hostcredentials.ErrNotFound
	}
	return *s.record, nil
}
func (s *memoryCredentialStore) Create(_ context.Context, r hostcredentials.Record) error {
	if s.record != nil {
		return hostcredentials.ErrExists
	}
	if err := r.Validate(); err != nil {
		return err
	}
	s.record = &r
	s.writes++
	return nil
}
func (s *memoryCredentialStore) Update(_ context.Context, patch func(*hostcredentials.Record) error) error {
	if s.record == nil {
		return hostcredentials.ErrNotFound
	}
	r := *s.record
	if err := patch(&r); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	s.record = &r
	s.writes++
	return nil
}
func (s *memoryCredentialStore) Delete(context.Context) error { s.record = nil; s.writes++; return nil }

func TestCredentialCLIInputsAndRedaction(t *testing.T) {
	ctx := context.Background()
	env := map[string]string{"CONTROL_PLANE_API_KEY": "ambient-secret-not-to-persist", "CONTROL_PLANE_TUNNEL_ID": "ambient-tunnel"}
	store := &memoryCredentialStore{}
	var out bytes.Buffer
	cli := credentialCLI{in: strings.NewReader("stdin-secret\n"), out: &out, getenv: func(k string) string { return env[k] }, open: func(path string) credentialStore { store.path = path; return store }}
	path := filepath.Join(t.TempDir(), "override.enc")
	if err := cli.execute(ctx, []string{"set", "--tunnel-id", "tunnel_cli", "--api-key-stdin", "--organization-id", "org-test", "--credentials-file", path}, ""); err != nil {
		t.Fatal(err)
	}
	if store.path != path || store.record.APIKey != "stdin-secret" || store.record.TunnelID != "tunnel_cli" {
		t.Fatal("explicit CLI input not used")
	}
	cli.in = strings.NewReader("replacement-secret\n")
	if err := cli.execute(ctx, []string{"update", "--api-key-stdin", "--unset", "organization-id"}, path); err != nil {
		t.Fatal(err)
	}
	if store.record.APIKey != "replacement-secret" || store.record.TunnelID != "tunnel_cli" || store.record.OrganizationID != "" {
		t.Fatal("partial update lost fields")
	}
	for _, action := range []string{"status", "doctor"} {
		out.Reset()
		before := store.writes
		if err := cli.execute(ctx, []string{action, "--json"}, path); err != nil {
			t.Fatal(err)
		}
		var status credentialStatus
		if err := json.Unmarshal(out.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if !status.Exists || !status.Readable || !status.APIKeyConfigured || status.Sources["api-key"] != "environment" {
			t.Fatal("incorrect status")
		}
		if store.writes != before || strings.Contains(out.String(), "secret") {
			t.Fatal("status/doctor wrote data or leaked key")
		}
	}
	if err := cli.execute(ctx, []string{"set", "--from-env"}, path); !errors.Is(err, hostcredentials.ErrExists) {
		t.Fatal("set overwrote record")
	}
	if err := cli.execute(ctx, []string{"delete"}, path); err != nil {
		t.Fatal(err)
	}
	if err := cli.execute(ctx, []string{"delete"}, path); err != nil {
		t.Fatal(err)
	}
	if err := cli.execute(ctx, []string{"set", "--from-env"}, path); err != nil {
		t.Fatal(err)
	}
	if store.record.APIKey != env["CONTROL_PLANE_API_KEY"] {
		t.Fatal("explicit --from-env not honored")
	}
}

func TestCredentialCLIRejectsInvalidAndNoninteractiveInputs(t *testing.T) {
	for _, args := range [][]string{
		{"set"}, {"unknown"}, {"set", "--api-key", "must-not-echo-secret"},
		{"set", "--from-env", "--api-key-stdin"}, {"set", "--unset", "base-url"},
		{"update", "--unset", "api-key"}, {"update", "--unset", "base-url", "--base-url", "https://example.test"},
		{"status", "--api-key-stdin"}, {"doctor", "--from-env"}, {"delete", "--tunnel-id", "x"},
		{"set", "--json"}, {"set", "--credentials-file="}, {"set", "unexpected-positional-secret"},
	} {
		store := &memoryCredentialStore{}
		var out bytes.Buffer
		cli := credentialCLI{in: strings.NewReader(""), out: &out, getenv: func(string) string { return "" }, open: func(path string) credentialStore { store.path = path; return store }}
		err := cli.execute(context.Background(), args, filepath.Join(t.TempDir(), "test.enc"))
		if err == nil || store.writes != 0 {
			t.Fatalf("invalid input accepted: %v", args)
		}
		if strings.Contains(err.Error(), "must-not-echo-secret") || strings.Contains(err.Error(), "unexpected-positional-secret") {
			t.Fatal("argument echoed in error")
		}
	}
}

func TestSettingsSavedAndEnvironmentPriority(t *testing.T) {
	r := hostcredentials.Record{TunnelID: "saved-tunnel", APIKey: "saved-key", BaseURL: "https://saved.example", OrganizationID: "org-saved"}
	env := map[string]string{"CONTROL_PLANE_TUNNEL_ID": "env-tunnel"}
	cfg, err := settingsFromRecord(func(k string) string { return env[k] }, r)
	if err != nil || cfg.Tunnel.TunnelID != "env-tunnel" || cfg.Tunnel.APIKey != "saved-key" || cfg.Tunnel.ControlPlaneBaseURL != r.BaseURL || cfg.Tunnel.OrganizationID != r.OrganizationID {
		t.Fatal("per-field override failed", err)
	}
	// A deliberately unreadable path must never be touched for stdio or a full
	// environment; these modes work without an OS keystore or user profile.
	for _, values := range []map[string]string{
		{"HOST_MONITOR_TRANSPORT": "stdio"},
		{"CONTROL_PLANE_TUNNEL_ID": "env-tunnel", "CONTROL_PLANE_API_KEY": "env-key"},
	} {
		if _, err := settingsWithCredentials(context.Background(), func(k string) string { return values[k] }, "bad\x00path"); err != nil {
			t.Fatal("environment-only mode read credentials", err)
		}
	}
}

func TestReadOnlyCredentialCommandsCreateNothing(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "missing-directory", "credentials.enc")
	for _, action := range []string{"status", "doctor", "delete"} {
		_ = execute(context.Background(), []string{"credentials", action, "--credentials-file", path}, strings.NewReader(""), io.Discard, func(string) string { return "" })
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("read-only commands created files")
	}
}
