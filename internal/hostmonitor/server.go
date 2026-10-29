package hostmonitor

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

const DefaultTimeout = 10 * time.Second

type EmptyArgs struct{}

type CPUArgs struct {
	SampleMS int `json:"sample_ms,omitempty" jsonschema:"Sampling interval in milliseconds; default 200, minimum 100, maximum 2000."`
}

type ProcessArgs struct {
	Offset int   `json:"offset,omitempty" jsonschema:"Zero-based offset into the current list sorted by PID."`
	Limit  int   `json:"limit,omitempty" jsonschema:"Maximum processes returned; default 100, maximum 500."`
	PID    int32 `json:"pid,omitempty" jsonschema:"Optional positive PID to inspect instead of a page of processes."`
}

// NewServer registers only observational tools. It opens no listeners, creates
// no files, and leaves the choice of MCP transport to its caller.
func NewServer(version string, timeout time.Duration) *mcp.Server {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "host-monitor", Version: version}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}},
		Instructions: "Read-only host monitoring. Byte fields are bytes and percentages range from 0 to 100. Disk/network I/O counters are cumulative, not per-second rates. Compare snapshots from the same host and device to calculate rates; counters can reset. Process pages are fresh snapshots sorted by PID. Missing fields mean unavailable or access denied, not zero. Logged-in users are sessions, not all configured accounts. No tools modify the host.",
	})
	register(s, timeout, "host_info", "Get hostname, OS, architecture, uptime and logical CPU count.", hostInfo)
	register(s, timeout, "cpu_usage", "Sample total and per-logical-CPU utilization over a bounded interval.", cpuUsage)
	register(s, timeout, "memory_usage", "Get physical RAM total, available and used bytes and utilization.", memoryUsage)
	register(s, timeout, "swap_usage", "Get Linux swap or Windows pagefile capacity and current usage; no devices means disabled.", swapUsage)
	register(s, timeout, "disk_usage", "Get capacity and usage of local mounted filesystems; inaccessible volumes appear as warnings.", diskUsage)
	register(s, timeout, "disk_io", "Get cumulative read/write bytes and operation counts per disk; these are not rates.", diskIO)
	register(s, timeout, "network_io", "Get cumulative traffic and error counters per network interface; these are not rates.", networkIO)
	register(s, timeout, "process_list", "List processes sorted by PID, or inspect one PID. Missing details report access denied or process exit. No process command lines or environment variables are collected.", processList)
	register(s, timeout, "logged_in_users", "List logged-in sessions, including disconnected Windows sessions. This is not an account database listing.", loggedInUsers)
	register(s, timeout, "cpu_info", "Get OS-reported CPU models, vendors and physical/logical CPU configuration. Missing values mean unavailable.", cpuInfo)
	register(s, timeout, "gpu_info", "List OS-reported graphics/video controllers and existing driver information. Virtual or software adapters may be included. An unavailable source is distinct from an empty device list.", gpuInfo)
	register(s, timeout, "device_list", "List the OS's existing device inventory without hardware probes or rescans. Sorted, bounded pages; optional pci/usb bus filter.", deviceList)
	register(s, timeout, "temperatures", "Read temperatures already exposed by the OS or existing sensor providers, with sensor names and sources. Never installs/loads drivers or enables sensors. An empty list with source status is valid; thermal zones are not automatically CPU cores.", temperatures)
	registerPlatformTools(s, timeout)
	return s
}

func register[In, Out any](s *mcp.Server, timeout time.Duration, name, description string, collect func(context.Context, In) (Out, error)) {
	no := false
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{
		ReadOnlyHint: true, DestructiveHint: &no, OpenWorldHint: &no,
	}}, func(ctx context.Context, _ *mcp.CallToolRequest, args In) (*mcp.CallToolResult, Out, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var zero Out
		if err := ctx.Err(); err != nil {
			return nil, zero, err
		}
		out, err := collect(ctx, args)
		if err == nil {
			err = ctx.Err()
		}
		return nil, out, err
	})
}

func snapshot() Snapshot {
	return Snapshot{ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), OS: runtime.GOOS}
}

func cpuUsage(ctx context.Context, args CPUArgs) (CPUUsage, error) {
	if args.SampleMS == 0 {
		args.SampleMS = 200
	}
	if args.SampleMS < 100 || args.SampleMS > 2000 {
		return CPUUsage{}, fmt.Errorf("sample_ms must be between 100 and 2000")
	}
	values, err := cpu.PercentWithContext(ctx, time.Duration(args.SampleMS)*time.Millisecond, true)
	if err != nil {
		return CPUUsage{}, err
	}
	if len(values) == 0 {
		return CPUUsage{}, fmt.Errorf("no CPU samples available")
	}
	var total float64
	for _, v := range values {
		total += v
	}
	return CPUUsage{Snapshot: snapshot(), SampleMS: args.SampleMS, UsedPercent: total / float64(len(values)), PerCPUPercent: values}, nil
}

func memoryUsage(ctx context.Context, _ EmptyArgs) (MemoryUsage, error) {
	v, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return MemoryUsage{}, err
	}
	return MemoryUsage{Snapshot: snapshot(), TotalBytes: v.Total, AvailableBytes: v.Available, UsedBytes: v.Used, UsedPercent: v.UsedPercent}, nil
}

func swapUsage(ctx context.Context, _ EmptyArgs) (SwapUsage, error) {
	devices, err := mem.SwapDevicesWithContext(ctx)
	if err != nil {
		return SwapUsage{}, err
	}
	out := SwapUsage{Snapshot: snapshot(), Kind: "swap", Devices: []SwapDevice{}}
	if runtime.GOOS == "windows" {
		out.Kind = "pagefile"
	}
	for _, device := range devices {
		out.Devices = append(out.Devices, SwapDevice{Name: device.Name, UsedBytes: device.UsedBytes, FreeBytes: device.FreeBytes})
		out.UsedBytes += device.UsedBytes
		out.FreeBytes += device.FreeBytes
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].Name < out.Devices[j].Name })
	out.TotalBytes = out.UsedBytes + out.FreeBytes
	if out.TotalBytes > 0 {
		out.UsedPercent = 100 * float64(out.UsedBytes) / float64(out.TotalBytes)
	}
	return out, nil
}

func networkIO(ctx context.Context, _ EmptyArgs) (NetworkIO, error) {
	values, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return NetworkIO{}, err
	}
	out := NetworkIO{Snapshot: snapshot(), Interfaces: []NetworkCounter{}}
	for _, v := range values {
		out.Interfaces = append(out.Interfaces, NetworkCounter{Name: v.Name, BytesSent: v.BytesSent, BytesRecv: v.BytesRecv,
			PacketsSent: v.PacketsSent, PacketsRecv: v.PacketsRecv, ErrorsIn: v.Errin, ErrorsOut: v.Errout, DropsIn: v.Dropin, DropsOut: v.Dropout})
	}
	sort.Slice(out.Interfaces, func(i, j int) bool { return out.Interfaces[i].Name < out.Interfaces[j].Name })
	return out, nil
}

func processList(ctx context.Context, args ProcessArgs) (ProcessList, error) {
	if args.Limit == 0 {
		args.Limit = 100
	}
	if args.Offset < 0 || args.Limit < 1 || args.Limit > 500 || args.PID < 0 {
		return ProcessList{}, fmt.Errorf("offset and pid must be nonnegative; limit must be between 1 and 500")
	}
	if args.PID > 0 && args.Offset != 0 {
		return ProcessList{}, fmt.Errorf("offset cannot be combined with pid")
	}
	entries, err := processEntries(ctx)
	if err != nil {
		return ProcessList{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].PID < entries[j].PID })
	if args.PID > 0 {
		found := false
		for _, entry := range entries {
			if entry.PID == args.PID {
				entries = []Process{entry}
				found = true
				break
			}
		}
		if !found {
			return ProcessList{}, fmt.Errorf("pid %d is not present in the current process snapshot", args.PID)
		}
	}
	out := ProcessList{Snapshot: snapshot(), Total: len(entries), Offset: args.Offset, Processes: []Process{}}
	start := min(args.Offset, len(entries))
	end := start + min(args.Limit, len(entries)-start)
	for _, entry := range entries[start:end] {
		if err := ctx.Err(); err != nil {
			return ProcessList{}, err
		}
		out.Processes = append(out.Processes, processDetails(ctx, entry))
	}
	out.HasMore = end < len(entries)
	out.NextOffset = end
	return out, nil
}
