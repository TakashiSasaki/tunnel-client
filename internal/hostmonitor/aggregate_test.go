// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostmonitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func decodeSnapshotItem[T any](t *testing.T, out HostSnapshot, name string) T {
	t.Helper()
	data, ok := out.Results[name]
	if !ok {
		t.Fatalf("missing %s result: %+v", name, out)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSnapshotOverMCP(t *testing.T) {
	session, ctx := connectMonitor(t)
	include := []string{"host_info", "cpu_usage", "memory_usage", "swap_usage", "disk_usage", "disk_io", "network_io", "process_list", "logged_in_users", "cpu_info", "gpu_info", "device_list", "temperatures"}
	out := readTool[HostSnapshot](t, session, ctx, "host_snapshot", SnapshotArgs{
		Include: include, CPU: CPUArgs{SampleMS: 100}, Process: ProcessArgs{Limit: 2}, Devices: DeviceArgs{Bus: "usb", Limit: 3},
	})
	if len(out.Results)+len(out.Errors) != len(include) || len(out.Include) != len(include) || out.Complete != (len(out.Errors) == 0) {
		t.Fatalf("incomplete accounting: %+v", out)
	}
	for _, name := range include {
		_, result := out.Results[name]
		_, failure := out.Errors[name]
		if result == failure {
			t.Fatalf("%s must have exactly one result or error", name)
		}
	}
	start, err := time.Parse(time.RFC3339Nano, out.Snapshot.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC3339Nano, out.FinishedAt)
	if err != nil || end.Before(start) {
		t.Fatalf("invalid collection interval: %s..%s", out.Snapshot.ObservedAt, out.FinishedAt)
	}
	if got := decodeSnapshotItem[MemoryUsage](t, out, "memory_usage"); got.TotalBytes == 0 {
		t.Fatal("missing RAM measurement")
	}
	if got := decodeSnapshotItem[CPUUsage](t, out, "cpu_usage"); got.SampleMS != 100 {
		t.Fatal("CPU arguments lost")
	}
	if got := decodeSnapshotItem[ProcessList](t, out, "process_list"); len(got.Processes) > 2 {
		t.Fatal("process limit lost")
	}
	devices := decodeSnapshotItem[DeviceList](t, out, "device_list")
	if len(devices.Devices) > 3 {
		t.Fatal("device limit lost")
	}
	for _, device := range devices.Devices {
		if device.Bus != "usb" {
			t.Fatal("device bus filter lost")
		}
	}
	t.Logf("aggregate: %d results, errors: %v", len(out.Results), out.Errors)

	partial := readTool[HostSnapshot](t, session, ctx, "host_snapshot", SnapshotArgs{
		Include: []string{"memory_usage", "cpu_usage"}, CPU: CPUArgs{SampleMS: 1},
	})
	if partial.Complete || len(partial.Results) != 1 || !strings.Contains(partial.Errors["cpu_usage"], "sample_ms") {
		t.Fatalf("failed collector discarded success: %+v", partial)
	}
	decodeSnapshotItem[MemoryUsage](t, partial, "memory_usage")
}

func TestSnapshotRejectsInvalidSelectionOverMCP(t *testing.T) {
	session, ctx := connectMonitor(t)
	for _, args := range []any{
		map[string]any{}, SnapshotArgs{Include: []string{}}, SnapshotArgs{Include: []string{"memory_usage", "memory_usage"}},
		SnapshotArgs{Include: []string{"memory"}}, SnapshotArgs{Include: []string{"screenshot"}},
		SnapshotArgs{Include: []string{"host_snapshot"}}, SnapshotArgs{Include: make([]string, 14)},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "host_snapshot", Arguments: args})
		if err == nil && !result.IsError {
			t.Fatalf("accepted invalid selection: %+v", args)
		}
	}
}

func TestSnapshotSharedTimeoutOverMCP(t *testing.T) {
	session, ctx := connectMonitorWithTimeout(t, 500*time.Millisecond)
	out := readTool[HostSnapshot](t, session, ctx, "host_snapshot", SnapshotArgs{
		Include: []string{"memory_usage", "cpu_usage"}, CPU: CPUArgs{SampleMS: 2000},
	})
	if out.Complete || len(out.Results) != 1 || out.Errors["cpu_usage"] != context.DeadlineExceeded.Error() {
		t.Fatalf("MCP discarded partial result at deadline: %+v", out)
	}
	decodeSnapshotItem[MemoryUsage](t, out, "memory_usage")
}

func TestSnapshotTimeoutRetainsSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	release := make(chan struct{})
	finished := make(chan struct{})
	defer func() { close(release); <-finished }()
	out, err := collectSnapshot(ctx, []string{"fast", "blocked"}, map[string]snapshotCollector{
		"fast": func(context.Context) (any, error) { return "retained", nil },
		"blocked": func(context.Context) (any, error) {
			defer close(finished)
			<-release // Simulate an OS call which cannot be interrupted.
			return "late", nil
		},
	})
	if err != nil || out.Complete || out.Results["fast"] != "retained" || out.Errors["blocked"] != context.DeadlineExceeded.Error() {
		t.Fatalf("invalid timeout response: %+v, %v", out, err)
	}
	if _, ok := out.Results["blocked"]; ok {
		t.Fatal("late result returned")
	}
	// A late OS result only writes to its buffered channel, never to out.
}

func TestSnapshotConcurrencyAndFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var active, peak atomic.Int32
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	defer close(release)
	collectors := make(map[string]snapshotCollector)
	var include []string
	for i := range 8 {
		name := fmt.Sprint(i)
		include = append(include, name)
		collectors[name] = func(ctx context.Context) (any, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			started <- struct{}{}
			select {
			case <-release:
				return nil, errors.New("provider unavailable")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	done := make(chan HostSnapshot, 1)
	go func() { out, _ := collectSnapshot(ctx, include, collectors); done <- out }()
	for range 4 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("collectors did not start")
		}
	}
	// Release jobs by sending tokens; defer closes the channel on any failure.
	for range 8 {
		select {
		case release <- struct{}{}:
		case <-ctx.Done():
			t.Fatal("collectors did not finish")
		}
	}
	select {
	case out := <-done:
		if peak.Load() != 4 || out.Complete || len(out.Results) != 0 || len(out.Errors) != 8 {
			t.Fatalf("concurrency/failure accounting: peak=%d out=%+v", peak.Load(), out)
		}
	case <-ctx.Done():
		t.Fatal("snapshot did not finish")
	}
}
