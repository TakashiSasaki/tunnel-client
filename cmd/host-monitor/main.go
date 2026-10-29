// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

// host-monitor is a single-binary MCP server, tunnel client and credential CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tunnelclient "github.com/openai/tunnel-client"
	"github.com/openai/tunnel-client/internal/hostcredentials"
	"github.com/openai/tunnel-client/internal/hostmonitor"
	"github.com/openai/tunnel-client/pkg/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Getenv); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		var usage commandError
		if errors.As(err, &usage) {
			os.Exit(2)
		}
		if errors.Is(err, hostcredentials.ErrNotFound) {
			os.Exit(3)
		}
		if errors.Is(err, hostcredentials.ErrUnavailable) {
			os.Exit(4)
		}
		os.Exit(1)
	}
}

const mainHelp = `host-monitor: read-only MCP host monitoring in one executable.

  host-monitor [--credentials-file PATH]     Start the monitor
  host-monitor credentials --help          Manage encrypted credentials
  host-monitor --version

Environment variables override saved credentials. A complete tunnel ID and API
key in the environment bypass the saved file entirely; stdio needs no credentials.
  HOST_MONITOR_TRANSPORT=tunnel (default) or stdio
  CONTROL_PLANE_TUNNEL_ID
  CONTROL_PLANE_API_KEY
  CONTROL_PLANE_BASE_URL (optional)
  CONTROL_PLANE_ORGANIZATION_ID (optional)
  HOST_MONITOR_CREDENTIALS_FILE (optional; overridden by --credentials-file)
  HOST_MONITOR_ADMIN_CREDENTIALS_FILE (credentials --type admin only)
  OPENAI_ADMIN_KEY (credentials set/update --type admin --from-env only)
  HOST_MONITOR_TIMEOUT=10s (100ms..120s)

No local HTTP listeners or plaintext configuration files are used.
`

func execute(ctx context.Context, args []string, in io.Reader, out io.Writer, getenv func(string) string) error {
	flags := flag.NewFlagSet("host-monitor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("credentials-file", "", "")
	showVersion := flags.Bool("version", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = fmt.Fprint(out, mainHelp)
			return err
		}
		return usageError("invalid arguments; use --help")
	}
	if *showVersion {
		if flags.NArg() != 0 {
			return usageError("--version does not accept a subcommand")
		}
		_, err := fmt.Fprintln(out, "host-monitor "+version.Version)
		return err
	}
	var emptyPath bool
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "credentials-file" && *path == "" {
			emptyPath = true
		}
	})
	if emptyPath {
		return usageError("--credentials-file cannot be empty")
	}
	if flags.NArg() > 0 {
		if flags.Arg(0) != "credentials" {
			return usageError("unexpected argument; use --help")
		}
		return (credentialCLI{in: in, out: out, getenv: getenv, open: func(path string, kind hostcredentials.Kind) credentialStore {
			return hostcredentials.NewForKind(path, kind)
		}}).execute(ctx, flags.Args()[1:], *path)
	}
	cfg, err := settingsWithCredentials(ctx, getenv, *path)
	if err != nil {
		return err
	}
	return run(ctx, cfg)
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
