// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	tunnelclient "github.com/openai/tunnel-client"
	"github.com/openai/tunnel-client/internal/hostcredentials"
	"github.com/openai/tunnel-client/internal/hostmonitor"
)

type settings struct {
	Transport string
	Timeout   time.Duration
	Tunnel    tunnelclient.Config
}

func settingsFromEnvironment(getenv func(string) string) (settings, error) {
	return settingsFromRecord(getenv, hostcredentials.Record{})
}

func settingsWithCredentials(ctx context.Context, getenv func(string) string, override string) (settings, error) {
	mode := strings.TrimSpace(getenv("HOST_MONITOR_TRANSPORT"))
	if (mode != "" && mode != "tunnel") ||
		(strings.TrimSpace(getenv("CONTROL_PLANE_TUNNEL_ID")) != "" && strings.TrimSpace(getenv("CONTROL_PLANE_API_KEY")) != "") {
		return settingsFromEnvironment(getenv)
	}
	path, err := hostcredentials.ResolvePath(override, getenv)
	if err != nil {
		return settings{}, err
	}
	record, err := hostcredentials.New(path).Load(ctx)
	if err != nil && !errors.Is(err, hostcredentials.ErrNotFound) {
		return settings{}, err
	}
	return settingsFromRecord(getenv, record)
}

func settingsFromRecord(getenv func(string) string, record hostcredentials.Record) (settings, error) {
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
		cfg.Tunnel.TunnelID = record.TunnelID
	}
	if cfg.Tunnel.APIKey == "" {
		cfg.Tunnel.APIKey = record.APIKey
	}
	if cfg.Tunnel.ControlPlaneBaseURL == "" {
		cfg.Tunnel.ControlPlaneBaseURL = record.BaseURL
	}
	if cfg.Tunnel.OrganizationID == "" {
		cfg.Tunnel.OrganizationID = record.OrganizationID
	}
	if cfg.Tunnel.TunnelID == "" {
		return settings{}, fmt.Errorf("CONTROL_PLANE_TUNNEL_ID is required in tunnel mode; alternatively run credentials set")
	}
	if cfg.Tunnel.APIKey == "" {
		return settings{}, fmt.Errorf("CONTROL_PLANE_API_KEY is required in tunnel mode; alternatively run credentials set")
	}
	return cfg, nil
}
