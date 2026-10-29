// host-monitor is an environment-only, single-binary MCP server and tunnel client.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tunnelclient "github.com/openai/tunnel-client"
	"github.com/openai/tunnel-client/internal/hostmonitor"
	"github.com/openai/tunnel-client/pkg/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version":
			fmt.Println("host-monitor " + version.Version)
			return
		case "--help", "-h":
			fmt.Println("host-monitor: read-only MCP host monitoring in one executable.\n\nConfiguration uses environment variables only:\n  HOST_MONITOR_TRANSPORT=tunnel (default) or stdio\n  CONTROL_PLANE_TUNNEL_ID (required for tunnel)\n  CONTROL_PLANE_API_KEY (required for tunnel)\n  CONTROL_PLANE_BASE_URL (optional)\n  CONTROL_PLANE_ORGANIZATION_ID (optional)\n  HOST_MONITOR_TIMEOUT=10s (100ms..120s)\n\nNo configuration files or local HTTP listeners are used.")
			return
		default:
			fmt.Fprintln(os.Stderr, "unexpected argument; use --help (configuration is environment-only)")
			os.Exit(2)
		}
	}
	cfg, err := settingsFromEnvironment(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg settings) (runErr error) {
	server := hostmonitor.NewServer(version.Version, cfg.Timeout)
	if cfg.Transport == "stdio" {
		return server.Run(ctx, &mcp.StdioTransport{})
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	client, err := tunnelclient.New(cfg.Tunnel, clientTransport)
	if err != nil {
		return err
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx, serverTransport) }()
	if err := client.Start(ctx); err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Stop(stopCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("stop tunnel runtime: %w", err))
		}
	}()
	// Process startup is distinct from a successful control-plane poll.
	ready := client.Ready()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-client.Done():
			return errors.New("tunnel runtime stopped")
		case err := <-serverDone:
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				return errors.New("embedded MCP server stopped")
			}
			return fmt.Errorf("embedded MCP server: %w", err)
		case <-ready:
			fmt.Fprintln(os.Stderr, "host-monitor: tunnel polling connected")
			ready = nil
		}
	}
}
