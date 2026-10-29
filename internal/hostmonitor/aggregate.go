// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostmonitor

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type SnapshotArgs struct {
	Include []string    `json:"include" jsonschema:"Required nonempty list of distinct monitoring tool names: host_info, cpu_usage, memory_usage, swap_usage, disk_usage, disk_io, network_io, process_list, logged_in_users, cpu_info, gpu_info, device_list, temperatures. Screenshots and nested snapshots are not supported."`
	CPU     CPUArgs     `json:"cpu,omitempty" jsonschema:"Options used only when cpu_usage is included; same defaults and limits as cpu_usage."`
	Process ProcessArgs `json:"process,omitempty" jsonschema:"Options used only when process_list is included; same pagination and PID limits as process_list."`
	Devices DeviceArgs  `json:"devices,omitempty" jsonschema:"Options used only when device_list is included; same bus and pagination limits as device_list."`
}

// HostSnapshot retains successful results when another collector fails or the
// shared time budget expires. Individual results retain their own timestamps.
type HostSnapshot struct {
	Snapshot   Snapshot          `json:"snapshot"`
	FinishedAt string            `json:"finished_at"`
	Include    []string          `json:"include"`
	Complete   bool              `json:"complete"`
	Results    map[string]any    `json:"results"`
	Errors     map[string]string `json:"errors"`
}

type snapshotCollector func(context.Context) (any, error)

func bindCollector[In, Out any](collect func(context.Context, In) (Out, error), args In) snapshotCollector {
	return func(ctx context.Context) (any, error) { return collect(ctx, args) }
}

func snapshotCollectors(args SnapshotArgs) map[string]snapshotCollector {
	return map[string]snapshotCollector{
		"host_info":       bindCollector(hostInfo, EmptyArgs{}),
		"cpu_usage":       bindCollector(cpuUsage, args.CPU),
		"memory_usage":    bindCollector(memoryUsage, EmptyArgs{}),
		"swap_usage":      bindCollector(swapUsage, EmptyArgs{}),
		"disk_usage":      bindCollector(diskUsage, EmptyArgs{}),
		"disk_io":         bindCollector(diskIO, EmptyArgs{}),
		"network_io":      bindCollector(networkIO, EmptyArgs{}),
		"process_list":    bindCollector(processList, args.Process),
		"logged_in_users": bindCollector(loggedInUsers, EmptyArgs{}),
		"cpu_info":        bindCollector(cpuInfo, EmptyArgs{}),
		"gpu_info":        bindCollector(gpuInfo, EmptyArgs{}),
		"device_list":     bindCollector(deviceList, args.Devices),
		"temperatures":    bindCollector(temperatures, EmptyArgs{}),
	}
}

func registerSnapshot(s *mcp.Server, timeout time.Duration) {
	no := false
	mcp.AddTool(s, &mcp.Tool{
		Name:        "host_snapshot",
		Description: "Collect selected read-only monitoring tools in one call. Pass their exact tool names in include. Results have the same shape as individual tools. Returns per-item errors alongside successful results, including on timeout; complete means all requested collectors succeeded, not that every OS field or sensor is available. Uses one shared timeout and at most four concurrent collectors. Measurements are not atomic. Screenshots must be requested separately.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &no, OpenWorldHint: &no},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args SnapshotArgs) (*mcp.CallToolResult, HostSnapshot, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		// Do not use register's post-collection ctx.Err check: a deadline is an
		// item error here, so already collected results must remain accessible.
		out, err := collectSnapshot(ctx, args.Include, snapshotCollectors(args))
		return nil, out, err
	})
}

func collectSnapshot(ctx context.Context, include []string, collectors map[string]snapshotCollector) (HostSnapshot, error) {
	if len(include) == 0 || len(include) > len(collectors) {
		return HostSnapshot{}, fmt.Errorf("include must contain between 1 and %d distinct monitoring tool names", len(collectors))
	}
	seen := make(map[string]bool, len(include))
	for _, name := range include {
		if _, ok := collectors[name]; !ok {
			return HostSnapshot{}, fmt.Errorf("unsupported include item %q; use a monitoring tool name (screenshots and nested snapshots are not supported)", name)
		}
		if seen[name] {
			return HostSnapshot{}, fmt.Errorf("duplicate include item %q", name)
		}
		seen[name] = true
	}
	out := HostSnapshot{Snapshot: snapshot(), Include: append([]string(nil), include...),
		Results: make(map[string]any), Errors: make(map[string]string)}
	type collected struct {
		name string
		data any
		err  error
	}
	jobs := make(chan string, len(include))
	// Each job sends once. The buffer lets a noncancelable OS query finish
	// safely after a deadline response, without modifying the returned maps.
	results := make(chan collected, len(include))
	for _, name := range include {
		jobs <- name
	}
	close(jobs)
	for range min(4, len(include)) {
		go func() {
			for name := range jobs {
				if ctx.Err() != nil {
					return
				}
				data, err := collectors[name](ctx)
				if err == nil {
					err = ctx.Err()
				}
				results <- collected{name: name, data: data, err: err}
			}
		}()
	}
	record := func(r collected) {
		if r.err != nil {
			out.Errors[r.name] = r.err.Error()
		} else {
			out.Results[r.name] = r.data
		}
	}
	for len(out.Results)+len(out.Errors) < len(include) {
		select {
		case r := <-results:
			record(r)
		case <-ctx.Done():
			// Retain completed results already queued before marking the rest.
			for {
				select {
				case r := <-results:
					record(r)
				default:
					for _, name := range include {
						if _, ok := out.Results[name]; !ok && out.Errors[name] == "" {
							out.Errors[name] = ctx.Err().Error()
						}
					}
					out.Complete = len(out.Errors) == 0
					out.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
					return out, nil
				}
			}
		}
	}
	out.Complete = len(out.Errors) == 0
	out.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return out, nil
}
