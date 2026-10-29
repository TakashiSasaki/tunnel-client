//go:build !windows

package hostmonitor

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerPlatformTools(_ *mcp.Server, _ time.Duration) {}
