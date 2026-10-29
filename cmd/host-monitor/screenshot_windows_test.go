//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/tunnel-client/internal/hostmonitor"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

// Verify the PNG survives the whole poll -> in-memory MCP -> response envelope
// path, including JSON base64 encoding, without writing the image to disk.
func TestScreenshotThroughTunnel(t *testing.T) {
	const tunnelID = "tunnel_0123456789abcdef0123456789abcdef"
	const apiKey = "screenshot-local-test-key"
	var unavailable atomic.Bool
	command := mocktunnelservice.CommandResponse{
		Command: mocktunnelservice.NewCommand("monitor-screen", json.RawMessage(`{"jsonrpc":"2.0","id":"screen","method":"tools/call","params":{"name":"screenshot","arguments":{"max_width":160,"max_height":90}}}`), nil),
		ExpectedResponses: []mocktunnelservice.ExpectedResponse{{RequestID: "monitor-screen", Assert: func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
			if response.ResponseCode != http.StatusOK {
				tb.Errorf("unexpected response code: %d", response.ResponseCode)
			}
			var payload struct {
				Result struct {
					IsError bool `json:"isError"`
					Content []struct {
						Type     string `json:"type"`
						Text     string `json:"text"`
						MIMEType string `json:"mimeType"`
						Data     string `json:"data"`
					} `json:"content"`
					StructuredContent hostmonitor.ScreenshotInfo `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal(response.JSONResponse, &payload); err != nil {
				tb.Error(err)
				return
			}
			if payload.Result.IsError {
				for _, c := range payload.Result.Content {
					if strings.Contains(c.Text, "interactive desktop unavailable") {
						unavailable.Store(true)
						return
					}
				}
				tb.Errorf("screenshot tool failed: %+v", payload.Result.Content)
				return
			}
			images := 0
			for _, c := range payload.Result.Content {
				if c.Type != "image" {
					continue
				}
				images++
				if c.MIMEType != "image/png" {
					tb.Error("unexpected image MIME type")
				}
				data, err := base64.StdEncoding.DecodeString(c.Data)
				if err != nil {
					tb.Error(err)
					return
				}
				config, err := png.DecodeConfig(bytes.NewReader(data))
				if err != nil {
					tb.Error(err)
					return
				}
				if config.Width != payload.Result.StructuredContent.Width || config.Height != payload.Result.StructuredContent.Height || config.Width > 160 || config.Height > 90 {
					tb.Error("invalid tunneled PNG dimensions")
				}
			}
			if images != 1 {
				tb.Errorf("expected one tunneled image, got %d", images)
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
	if unavailable.Load() {
		t.Skip("no interactive desktop in this Windows session; error propagation verified")
	}
}
