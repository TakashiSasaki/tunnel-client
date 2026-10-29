// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build !windows

package hostmonitor

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerPlatformTools(_ *mcp.Server, _ time.Duration) {}
