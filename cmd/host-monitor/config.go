// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	tunnelclient "github.com/openai/tunnel-client"
	"github.com/openai/tunnel-client/internal/hostmonitor"
)

type settings struct {
	Transport string
	Timeout   time.Duration
	Tunnel    tunnelclient.Config
}

func settingsFromEnvironment(getenv func(string) string) (settings, error) {
	cfg := settings{Transport: strings.TrimSpace(getenv("HOST_MONITOR_TRANSPORT")), Timeout: hostmonitor.DefaultTimeout}
	if cfg.Transport == "" {
		cfg.Transport = "tunnel"
	}
	if cfg.Transport != "tunnel" && cfg.Transport != "stdio" {
		return settings{}, fmt.Errorf("HOST_MONITOR_TRANSPORT must be tunnel or stdio")
	}
	if raw := strings.TrimSpace(getenv("HOST_MONITOR_TIMEOUT")); raw != "" {
		v, err := time.ParseDuration(raw)
		if err != nil || v < 100*time.Millisecond || v > 120*time.Second {
			return settings{}, fmt.Errorf("HOST_MONITOR_TIMEOUT must be a duration between 100ms and 120s")
		}
		cfg.Timeout = v
	}
	if cfg.Transport == "stdio" {
		return cfg, nil
	}
	cfg.Tunnel = tunnelclient.Config{
		TunnelID:            strings.TrimSpace(getenv("CONTROL_PLANE_TUNNEL_ID")),
		APIKey:              strings.TrimSpace(getenv("CONTROL_PLANE_API_KEY")),
		ControlPlaneBaseURL: strings.TrimSpace(getenv("CONTROL_PLANE_BASE_URL")),
		OrganizationID:      strings.TrimSpace(getenv("CONTROL_PLANE_ORGANIZATION_ID")),
		LogLevel:            slog.LevelWarn,
	}
	if cfg.Tunnel.TunnelID == "" {
		return settings{}, fmt.Errorf("CONTROL_PLANE_TUNNEL_ID is required in tunnel mode")
	}
	if cfg.Tunnel.APIKey == "" {
		return settings{}, fmt.Errorf("CONTROL_PLANE_API_KEY is required in tunnel mode")
	}
	return cfg, nil
}
