// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openai/tunnel-client/internal/hostcredentials"
)

func TestCredentialTypeIsRequiredBeforeOpeningStore(t *testing.T) {
	for _, action := range []string{"set", "update", "delete", "status", "doctor"} {
		for _, suffix := range [][]string{nil, {"--type", "other"}, {"--type", "admin", "--tunnel-id", "tunnel_test"}} {
			cli := credentialCLI{in: strings.NewReader(""), out: io.Discard, getenv: func(string) string { return "" }, open: func(string, hostcredentials.Kind) credentialStore {
				t.Fatal("invalid selection opened store")
				return nil
			}}
			if err := cli.execute(context.Background(), append([]string{action}, suffix...), ""); err == nil {
				t.Fatal("accepted missing/invalid type")
			}
		}
	}
}

func TestCLISelectsIndependentKeysAndEnvironmentSources(t *testing.T) {
	ctx := context.Background()
	env := map[string]string{"OPENAI_ADMIN_KEY": "admin-only-secret", "CONTROL_PLANE_API_KEY": "runtime-only-secret", "CONTROL_PLANE_TUNNEL_ID": "tunnel_test"}
	stores := map[hostcredentials.Kind]*memoryCredentialStore{hostcredentials.Runtime: {}, hostcredentials.Admin: {}}
	var output bytes.Buffer
	cli := credentialCLI{in: strings.NewReader(""), out: &output, getenv: func(k string) string { return env[k] }, open: func(path string, kind hostcredentials.Kind) credentialStore {
		s := stores[kind]
		s.path = path
		return s
	}}
	path := filepath.Join(t.TempDir(), "selected.enc")
	for _, kind := range []hostcredentials.Kind{hostcredentials.Runtime, hostcredentials.Admin} {
		if err := cli.execute(ctx, []string{"set", "--type", string(kind), "--from-env"}, path); err != nil {
			t.Fatal(err)
		}
		r := stores[kind].record
		if r.EffectiveKind() != kind {
			t.Fatal("wrong record type saved")
		}
		if kind == hostcredentials.Admin && (r.APIKey != env["OPENAI_ADMIN_KEY"] || r.TunnelID != "") {
			t.Fatal("admin imported runtime inputs")
		}
		if kind == hostcredentials.Runtime && r.APIKey != env["CONTROL_PLANE_API_KEY"] {
			t.Fatal("runtime imported admin key")
		}
		for _, action := range []string{"status", "doctor"} {
			output.Reset()
			if err := cli.execute(ctx, []string{action, "--type", string(kind), "--json"}, path); err != nil {
				t.Fatal(err)
			}
			var out credentialStatus
			if json.Unmarshal(output.Bytes(), &out) != nil || out.Kind != kind || !out.APIKeyConfigured {
				t.Fatal("incorrect typed status")
			}
			if kind == hostcredentials.Admin {
				if _, ok := out.Sources["tunnel-id"]; ok {
					t.Fatal("admin shows runtime source")
				}
			}
			if strings.Contains(output.String(), "only-secret") {
				t.Fatal("key leaked in output")
			}
		}
	}
	cli.in = strings.NewReader("new-admin-secret")
	if err := cli.execute(ctx, []string{"update", "--type", "admin", "--api-key-stdin"}, path); err != nil {
		t.Fatal(err)
	}
	if stores[hostcredentials.Runtime].record.APIKey != "runtime-only-secret" {
		t.Fatal("admin update affected runtime")
	}
	if err := cli.execute(ctx, []string{"delete", "--type", "admin"}, path); err != nil {
		t.Fatal(err)
	}
	if stores[hostcredentials.Runtime].record == nil || stores[hostcredentials.Admin].record != nil {
		t.Fatal("delete affected wrong type")
	}
	delete(env, "CONTROL_PLANE_API_KEY")
	if _, err := settingsFromEnvironment(func(k string) string { return env[k] }); err == nil {
		t.Fatal("runtime fell back to OPENAI_ADMIN_KEY")
	}
	if _, err := settingsFromRecord(func(string) string { return "" }, hostcredentials.Record{Kind: hostcredentials.Admin, APIKey: "admin-secret"}); err == nil {
		t.Fatal("monitor accepted admin record")
	}
}
