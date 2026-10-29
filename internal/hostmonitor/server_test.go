// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostmonitor

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connectMonitor(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	return connectMonitorWithTimeout(t, 20*time.Second)
}

func connectMonitorWithTimeout(t *testing.T, timeout time.Duration) (*mcp.ClientSession, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := NewServer("test", timeout)
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "monitor-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("MCP server did not stop")
		}
	})
	return session, ctx
}

func readTool[T any](t *testing.T, session *mcp.ClientSession, ctx context.Context, name string, args any) T {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s protocol failure: %v", name, err)
	}
	if result.IsError {
		t.Fatalf("%s tool failure: %+v", name, result.Content)
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReadOnlyMCPToolsAgainstHost(t *testing.T) {
	session, ctx := connectMonitor(t)
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := 14
	if runtime.GOOS == "windows" {
		expected++
	}
	if len(listed.Tools) != expected {
		t.Fatalf("expected %d monitoring tools, got %d", expected, len(listed.Tools))
	}
	for _, tool := range listed.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint {
			t.Fatalf("tool %s does not declare read-only behavior", tool.Name)
		}
	}
	host := readTool[HostInfo](t, session, ctx, "host_info", EmptyArgs{})
	if host.Hostname == "" || host.Snapshot.OS != runtime.GOOS || host.LogicalCPUs < 1 {
		t.Fatalf("invalid host identity: %+v", host)
	}
	if _, err := time.Parse(time.RFC3339Nano, host.Snapshot.ObservedAt); err != nil {
		t.Fatal(err)
	}
	memory := readTool[MemoryUsage](t, session, ctx, "memory_usage", EmptyArgs{})
	if memory.TotalBytes == 0 || memory.UsedBytes > memory.TotalBytes || memory.AvailableBytes > memory.TotalBytes {
		t.Fatalf("invalid RAM counters: %+v", memory)
	}
	cpu := readTool[CPUUsage](t, session, ctx, "cpu_usage", CPUArgs{SampleMS: 100})
	if len(cpu.PerCPUPercent) == 0 || cpu.UsedPercent < 0 || cpu.UsedPercent > 100 {
		t.Fatalf("invalid CPU samples: %+v", cpu)
	}
	swap := readTool[SwapUsage](t, session, ctx, "swap_usage", EmptyArgs{})
	if swap.Devices == nil || swap.TotalBytes != swap.UsedBytes+swap.FreeBytes || swap.UsedPercent < 0 || swap.UsedPercent > 100 {
		t.Fatalf("invalid swap counters: %+v", swap)
	}
	disks := readTool[DiskUsage](t, session, ctx, "disk_usage", EmptyArgs{})
	if len(disks.Volumes) == 0 {
		t.Fatalf("no local volumes: %+v", disks.Warnings)
	}
	for _, v := range disks.Volumes {
		if v.UsedBytes > v.TotalBytes || v.FreeBytes > v.TotalBytes {
			t.Fatalf("invalid volume counters: %+v", v)
		}
	}
	network := readTool[NetworkIO](t, session, ctx, "network_io", EmptyArgs{})
	if len(network.Interfaces) == 0 {
		t.Fatal("no network interface counters")
	}
	users := readTool[LoggedInUsers](t, session, ctx, "logged_in_users", EmptyArgs{})
	if users.Sessions == nil {
		t.Fatal("session list must encode an empty list, not null")
	}
	current := readTool[ProcessList](t, session, ctx, "process_list", ProcessArgs{PID: int32(os.Getpid())})
	if len(current.Processes) != 1 || current.Processes[0].PID != int32(os.Getpid()) || current.Processes[0].Name == "" || current.Processes[0].ResidentBytes == nil {
		t.Fatalf("current process was not inspectable: %+v", current)
	}
	page := readTool[ProcessList](t, session, ctx, "process_list", ProcessArgs{Limit: 2})
	if len(page.Processes) > 2 || page.NextOffset != len(page.Processes) || page.Total < len(page.Processes) {
		t.Fatalf("invalid bounded process page: %+v", page)
	}
	for i := 1; i < len(page.Processes); i++ {
		if page.Processes[i-1].PID >= page.Processes[i].PID {
			t.Fatal("process page not sorted by PID")
		}
	}
	pastEnd := readTool[ProcessList](t, session, ctx, "process_list", ProcessArgs{Offset: 1000000000, Limit: 2})
	if len(pastEnd.Processes) != 0 || pastEnd.HasMore {
		t.Fatalf("expected empty page: %+v", pastEnd)
	}
}

func TestDiskIOMCPTool(t *testing.T) {
	session, ctx := connectMonitor(t)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "disk_io", Arguments: EmptyArgs{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		// A host without an existing counter provider is a supported deployment.
		// Report the failure, rather than enabling counters or inventing zeroes.
		t.Skipf("host disk counters unavailable: %+v", result.Content)
	}
	raw, _ := json.Marshal(result.StructuredContent)
	var out DiskIO
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Devices == nil {
		t.Fatal("devices must be an array")
	}
	t.Logf("read I/O counters for %d devices", len(out.Devices))
}

func TestMCPRejectsUnboundedRequests(t *testing.T) {
	session, ctx := connectMonitor(t)
	for _, tc := range []struct {
		name string
		args any
	}{
		{"cpu_usage", CPUArgs{SampleMS: 1}}, {"cpu_usage", CPUArgs{SampleMS: 2001}},
		{"process_list", ProcessArgs{Offset: -1}}, {"process_list", ProcessArgs{Limit: 501}},
		{"process_list", ProcessArgs{PID: -1}}, {"process_list", ProcessArgs{PID: 1, Offset: 1}},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatalf("accepted invalid input: %+v", tc)
		}
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "terminate_process", Arguments: map[string]any{"pid": os.Getpid()}})
	if err == nil && !result.IsError {
		t.Fatal("unexpected mutating tool available")
	}
}

func TestCPUSamplingHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := cpuUsage(ctx, CPUArgs{SampleMS: 2000})
	if err == nil {
		t.Fatal("sampling ignored canceled context")
	}
}
