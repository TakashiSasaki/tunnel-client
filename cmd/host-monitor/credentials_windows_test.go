// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openai/tunnel-client/internal/hostcredentials"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

func TestCredentialCLIExecutableRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "credentials.enc")
	adminPath := filepath.Join(filepath.Dir(path), "credentials.admin.enc")
	call := func(input string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		binary := os.Getenv("HOST_MONITOR_TEST_BINARY")
		var cmd *exec.Cmd
		if binary != "" {
			cmd = exec.CommandContext(ctx, binary, args...)
		} else {
			cmd = exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCredentialCLIHelperProcess$", "--"}, args...)...)
		}
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if !strings.HasPrefix(key, "CONTROL_PLANE_") && !strings.HasPrefix(key, "HOST_MONITOR_") && !strings.HasPrefix(key, "OPENAI_") {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "HOST_MONITOR_CREDENTIAL_HELPER=1", "HOST_MONITOR_CREDENTIALS_FILE="+path, "HOST_MONITOR_ADMIN_CREDENTIALS_FILE="+adminPath)
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if strings.Contains(string(output), "first-test-secret") || strings.Contains(string(output), "replacement-test-secret") || strings.Contains(string(output), "admin-test-secret") {
			t.Fatal("key leaked by executable")
		}
		return string(output), err
	}
	if out, err := call("first-test-secret\n", "credentials", "set", "--type", "runtime", "--tunnel-id", "tunnel_test", "--api-key-stdin"); err != nil {
		t.Fatalf("set: %v %s", err, out)
	}
	if out, err := call("replacement-test-secret\n", "credentials", "update", "--type", "runtime", "--api-key-stdin"); err != nil {
		t.Fatalf("update: %v %s", err, out)
	}
	if out, err := call("admin-test-secret\n", "credentials", "set", "--type", "admin", "--api-key-stdin"); err != nil {
		t.Fatalf("admin set: %v %s", err, out)
	}
	if out, err := call("updated-admin-test-secret\n", "credentials", "update", "--type", "admin", "--api-key-stdin"); err != nil {
		t.Fatalf("admin update: %v %s", err, out)
	}
	if record, err := hostcredentials.NewForKind(adminPath, hostcredentials.Admin).Load(context.Background()); err != nil || record.APIKey != "updated-admin-test-secret" || record.TunnelID != "" {
		t.Fatal("admin DPAPI roundtrip failed", err)
	}
	if _, err := call("", "credentials", "delete", "--type", "admin", "--credentials-file", path); err == nil {
		t.Fatal("admin deletion accepted runtime file")
	}
	getenv := func(k string) string {
		if k == "HOST_MONITOR_CREDENTIALS_FILE" {
			return path
		}
		return ""
	}
	cfg, err := settingsWithCredentials(context.Background(), getenv, "")
	if err != nil || cfg.Tunnel.APIKey != "replacement-test-secret" || cfg.Tunnel.TunnelID != "tunnel_test" {
		t.Fatal("startup did not load stored credentials", err)
	}
	if _, err := settingsWithCredentials(context.Background(), func(string) string { return "" }, adminPath); !errors.Is(err, hostcredentials.ErrKind) {
		t.Fatal("monitor accepted admin file", err)
	}
	for _, action := range []string{"status", "doctor"} {
		out, err := call("", "credentials", action, "--type", "runtime", "--json")
		if err != nil {
			t.Fatalf("%s: %v %s", action, err, out)
		}
		var status credentialStatus
		if json.Unmarshal([]byte(out), &status) != nil || !status.Exists || !status.Readable || status.Path != path {
			t.Fatal("invalid status JSON")
		}
		out, err = call("", "credentials", action, "--type", "admin", "--json")
		if err != nil || json.Unmarshal([]byte(out), &status) != nil || status.Kind != hostcredentials.Admin || status.Path != adminPath || !status.Readable {
			t.Fatal("invalid admin status/doctor")
		}
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("replacement-test-secret")) {
		t.Fatal("plaintext written to store")
	}
	if out, err := call("", "credentials", "delete", "--type", "runtime"); err != nil {
		t.Fatalf("delete: %v %s", err, out)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("credential file not deleted")
	}
	if _, err := hostcredentials.NewForKind(adminPath, hostcredentials.Admin).Load(context.Background()); err != nil {
		t.Fatal("runtime delete affected admin file", err)
	}
	if _, err := settingsWithCredentials(context.Background(), getenv, ""); err == nil {
		t.Fatal("admin-only store supplied runtime credentials")
	}
	if out, err := call("", "credentials", "delete", "--type", "admin"); err != nil {
		t.Fatalf("admin delete: %v %s", err, out)
	}
	if _, err := os.Stat(adminPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("admin file not deleted")
	}
}

func TestCredentialCLIHelperProcess(t *testing.T) {
	if os.Getenv("HOST_MONITOR_CREDENTIAL_HELPER") != "1" {
		return
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if err := execute(context.Background(), args, os.Stdin, os.Stdout, os.Getenv); err != nil {
		io.WriteString(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestSavedCredentialsConnectThroughMockTunnel(t *testing.T) {
	const tunnelID = "tunnel_0123456789abcdef0123456789abcdef"
	const apiKey = "local-saved-credential-test-key"
	command := mocktunnelservice.CommandResponse{
		Command: mocktunnelservice.NewCommand("saved-monitor-memory", json.RawMessage(`{"jsonrpc":"2.0","id":"memory","method":"tools/call","params":{"name":"memory_usage","arguments":{}}}`), nil),
		ExpectedResponses: []mocktunnelservice.ExpectedResponse{{RequestID: "saved-monitor-memory", Assert: func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
			var payload struct {
				Result struct {
					IsError           bool `json:"isError"`
					StructuredContent struct {
						Total uint64 `json:"total_bytes"`
					} `json:"structuredContent"`
				} `json:"result"`
			}
			if json.Unmarshal(response.JSONResponse, &payload) != nil || response.ResponseCode != http.StatusOK || payload.Result.IsError || payload.Result.StructuredContent.Total == 0 {
				tb.Error("saved-credential tunnel query failed")
			}
		}}},
	}
	service := mocktunnelservice.NewMockTunnelService(mocktunnelservice.WithAPIKey(apiKey), mocktunnelservice.WithTunnelID(tunnelID), mocktunnelservice.WithInitializationPhaseCommandsWithoutSessionHeaders(), mocktunnelservice.WithCommandResponses(command))
	service.Start(t)
	path := filepath.Join(t.TempDir(), "private", "credentials.enc")
	if err := hostcredentials.New(path).Create(context.Background(), hostcredentials.Record{TunnelID: tunnelID, APIKey: apiKey, BaseURL: service.BaseURL().String()}); err != nil {
		t.Fatal(err)
	}
	cfg, err := settingsWithCredentials(context.Background(), func(string) string { return "" }, path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tunnel.PollTimeout = 10 * time.Millisecond
	cfg.Tunnel.LogWriter = io.Discard
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()
	if err := service.WaitUntilIdle(ctx); err != nil {
		t.Error(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("monitor did not stop")
	}
}
