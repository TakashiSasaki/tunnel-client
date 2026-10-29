package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openai/tunnel-client/internal/hostmonitor"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

func TestSettingsFromEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"tunnel requires identity", map[string]string{}, "CONTROL_PLANE_TUNNEL_ID"},
		{"tunnel requires key", map[string]string{"CONTROL_PLANE_TUNNEL_ID": "tunnel_example"}, "CONTROL_PLANE_API_KEY"},
		{"no credential fallback", map[string]string{"CONTROL_PLANE_TUNNEL_ID": "tunnel_example", "OPENAI_API_KEY": "do-not-print"}, "CONTROL_PLANE_API_KEY"},
		{"invalid mode", map[string]string{"HOST_MONITOR_TRANSPORT": "http"}, "HOST_MONITOR_TRANSPORT"},
		{"invalid timeout", map[string]string{"HOST_MONITOR_TRANSPORT": "stdio", "HOST_MONITOR_TIMEOUT": "0s"}, "HOST_MONITOR_TIMEOUT"},
		{"unbounded timeout", map[string]string{"HOST_MONITOR_TRANSPORT": "stdio", "HOST_MONITOR_TIMEOUT": "121s"}, "HOST_MONITOR_TIMEOUT"},
		{"stdio requires no key", map[string]string{"HOST_MONITOR_TRANSPORT": "stdio"}, ""},
		{"tunnel", map[string]string{"CONTROL_PLANE_TUNNEL_ID": "tunnel_example", "CONTROL_PLANE_API_KEY": "do-not-print", "HOST_MONITOR_TIMEOUT": "3s"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := settingsFromEnvironment(func(key string) string { return tc.env[key] })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected %s, got %v", tc.wantErr, err)
				}
				if strings.Contains(err.Error(), "do-not-print") {
					t.Fatal("configuration error leaked a credential")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Timeout <= 0 {
				t.Fatal("missing default timeout")
			}
		})
	}
}

// Run a real subprocess over stdio. No files are supplied in its working
// directory; protocol output must not be mixed with logs or startup messages.
func TestStdioProcessWithoutConfigFiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binary := os.Getenv("HOST_MONITOR_TEST_BINARY")
	var cmd *exec.Cmd
	if binary != "" {
		abs, err := filepath.Abs(binary)
		if err != nil {
			t.Fatal(err)
		}
		cmd = exec.CommandContext(ctx, abs)
	} else {
		cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStdioHelperProcess$")
	}
	dir := t.TempDir()
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOST_MONITOR_TRANSPORT=stdio", "HOST_MONITOR_HELPER_PROCESS=1", "CONTROL_PLANE_API_KEY=", "CONTROL_PLANE_TUNNEL_ID=")
	cmd.Stderr = io.Discard
	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-smoke", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	expected := 13
	if runtime.GOOS == "windows" {
		expected++
	}
	if err != nil || len(tools.Tools) != expected {
		t.Fatalf("tool discovery: %+v, %v", tools, err)
	}
	names := []string{"host_info", "memory_usage", "swap_usage", "disk_usage", "disk_io", "network_io", "logged_in_users", "process_list", "cpu_usage", "cpu_info", "gpu_info", "device_list", "temperatures"}
	if runtime.GOOS == "windows" {
		names = append(names, "screenshot")
	}
	for _, name := range names {
		args := map[string]any{}
		if name == "process_list" {
			args["limit"] = 2
		}
		if name == "cpu_usage" {
			args["sample_ms"] = 100
		}
		if name == "screenshot" {
			args["max_width"] = 160
			args["max_height"] = 90
		}
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if result.IsError {
			if name == "screenshot" {
				unavailable := false
				for _, content := range result.Content {
					if text, ok := content.(*mcp.TextContent); ok && strings.Contains(text.Text, "interactive desktop unavailable") {
						unavailable = true
					}
				}
				if unavailable {
					t.Log("no interactive desktop; screenshot error returned over stdio")
					continue
				}
			}
			if name == "disk_io" {
				t.Logf("existing disk counters unavailable: %+v", result.Content)
				continue
			}
			t.Fatalf("%s: %+v", name, result.Content)
		}
		if name == "screenshot" {
			images := 0
			for _, content := range result.Content {
				if img, ok := content.(*mcp.ImageContent); ok {
					images++
					config, err := png.DecodeConfig(bytes.NewReader(img.Data))
					if err != nil || img.MIMEType != "image/png" || config.Width < 1 || config.Width > 160 || config.Height < 1 || config.Height > 90 {
						t.Fatalf("invalid screenshot over stdio: %+v, %v", config, err)
					}
				}
			}
			if images != 1 {
				t.Fatalf("expected one screenshot image, got %d", images)
			}
		}
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("monitor created files in its working directory: %+v", entries)
	}
}

func TestStdioHelperProcess(t *testing.T) {
	if os.Getenv("HOST_MONITOR_HELPER_PROCESS") != "1" {
		return
	}
	cfg, err := settingsFromEnvironment(os.Getenv)
	if err == nil {
		err = run(context.Background(), cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestEmbeddedHostToolThroughTunnel(t *testing.T) {
	const tunnelID = "tunnel_0123456789abcdef0123456789abcdef"
	const apiKey = "host-monitor-local-test-key"
	command := mocktunnelservice.CommandResponse{
		Command: mocktunnelservice.NewCommand("monitor-memory", json.RawMessage(`{"jsonrpc":"2.0","id":"memory","method":"tools/call","params":{"name":"memory_usage","arguments":{}}}`), nil),
		ExpectedResponses: []mocktunnelservice.ExpectedResponse{{RequestID: "monitor-memory", Assert: func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
			if response.ResponseCode != http.StatusOK {
				tb.Errorf("unexpected response code %d", response.ResponseCode)
			}
			var payload struct {
				Result struct {
					IsError           bool                    `json:"isError"`
					StructuredContent hostmonitor.MemoryUsage `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal(response.JSONResponse, &payload); err != nil {
				tb.Error(err)
				return
			}
			if payload.Result.IsError || payload.Result.StructuredContent.TotalBytes == 0 {
				tb.Errorf("invalid tunneled memory response: %+v", payload)
			}
		}}},
	}
	controlPlane := mocktunnelservice.NewMockTunnelService(mocktunnelservice.WithAPIKey(apiKey), mocktunnelservice.WithTunnelID(tunnelID),
		mocktunnelservice.WithInitializationPhaseCommandsWithoutSessionHeaders(), mocktunnelservice.WithCommandResponses(command))
	controlPlane.Start(t)
	cfg, err := settingsFromEnvironment(func(key string) string {
		return map[string]string{
			"CONTROL_PLANE_TUNNEL_ID": tunnelID, "CONTROL_PLANE_API_KEY": apiKey, "CONTROL_PLANE_BASE_URL": controlPlane.BaseURL().String(),
		}[key]
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tunnel.PollTimeout = 10 * time.Millisecond
	cfg.Tunnel.LogWriter = io.Discard
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()
	if err := controlPlane.WaitUntilIdle(ctx); err != nil {
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
	if responses := controlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched); len(responses) != 3 {
		t.Errorf("expected initialize, initialized and tool responses; got %d", len(responses))
	}
}
