//go:build !windows

package hostmonitor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sort"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/process"
)

func hostInfo(ctx context.Context, _ EmptyArgs) (HostInfo, error) {
	v, err := host.InfoWithContext(ctx)
	if err != nil {
		return HostInfo{}, err
	}
	return HostInfo{Snapshot: snapshot(), Hostname: v.Hostname, Architecture: runtime.GOARCH,
		Platform: v.Platform, PlatformVersion: v.PlatformVersion, UptimeSeconds: v.Uptime, LogicalCPUs: runtime.NumCPU()}, nil
}

func diskUsage(ctx context.Context, _ EmptyArgs) (DiskUsage, error) {
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return DiskUsage{}, err
	}
	out := DiskUsage{Snapshot: snapshot(), Volumes: []Volume{}}
	seen := map[string]bool{}
	for _, p := range partitions {
		if err := ctx.Err(); err != nil {
			return DiskUsage{}, err
		}
		if seen[p.Mountpoint] {
			continue
		}
		seen[p.Mountpoint] = true
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil {
			out.Warnings = append(out.Warnings, p.Mountpoint+": "+err.Error())
			continue
		}
		var percent float64
		if u.Total > 0 {
			percent = 100 * float64(u.Used) / float64(u.Total)
		}
		out.Volumes = append(out.Volumes, Volume{Device: p.Device, Mountpoint: p.Mountpoint, Filesystem: p.Fstype,
			TotalBytes: u.Total, FreeBytes: u.Total - u.Used, AvailableBytes: u.Free, UsedBytes: u.Used, UsedPercent: percent})
	}
	sort.Slice(out.Volumes, func(i, j int) bool { return out.Volumes[i].Mountpoint < out.Volumes[j].Mountpoint })
	return out, nil
}

func diskIO(ctx context.Context, _ EmptyArgs) (DiskIO, error) {
	values, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return DiskIO{}, err
	}
	out := DiskIO{Snapshot: snapshot(), Devices: []DiskCounter{}}
	for name, v := range values {
		out.Devices = append(out.Devices, DiskCounter{Device: name, ReadBytes: v.ReadBytes,
			WriteBytes: v.WriteBytes, ReadCount: v.ReadCount, WriteCount: v.WriteCount})
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].Device < out.Devices[j].Device })
	return out, nil
}

func processEntries(ctx context.Context) ([]Process, error) {
	pids, err := process.PidsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]Process, 0, len(pids))
	for _, pid := range pids {
		entries = append(entries, Process{PID: pid})
	}
	return entries, nil
}

func processDetails(ctx context.Context, out Process) Process {
	p, err := process.NewProcessWithContext(ctx, out.PID)
	if err != nil {
		out.Unavailable = []string{"process: " + err.Error()}
		return out
	}
	if v, err := p.NameWithContext(ctx); err == nil {
		out.Name = v
	} else {
		out.Unavailable = append(out.Unavailable, "name: "+err.Error())
	}
	if v, err := p.PpidWithContext(ctx); err == nil {
		out.ParentPID = &v
	} else {
		out.Unavailable = append(out.Unavailable, "parent_pid: "+err.Error())
	}
	if v, err := p.UsernameWithContext(ctx); err == nil {
		out.Username = v
	} else {
		out.Unavailable = append(out.Unavailable, "username: "+err.Error())
	}
	if v, err := p.MemoryInfoWithContext(ctx); err == nil {
		out.ResidentBytes = &v.RSS
	} else {
		out.Unavailable = append(out.Unavailable, "resident_bytes: "+err.Error())
	}
	if v, err := p.TimesWithContext(ctx); err == nil {
		seconds := v.User + v.System
		out.CPUSeconds = &seconds
	} else {
		out.Unavailable = append(out.Unavailable, "cpu_seconds: "+err.Error())
	}
	if v, err := p.NumThreadsWithContext(ctx); err == nil {
		out.Threads = &v
	} else {
		out.Unavailable = append(out.Unavailable, "threads: "+err.Error())
	}
	if v, err := p.CreateTimeWithContext(ctx); err == nil {
		out.StartedUnixMS = &v
	} else {
		out.Unavailable = append(out.Unavailable, "started_unix_ms: "+err.Error())
	}
	return out
}

func loggedInUsers(ctx context.Context, _ EmptyArgs) (LoggedInUsers, error) {
	users, err := host.UsersWithContext(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LoggedInUsers{Snapshot: snapshot(), Sessions: []LoginSession{}, Warnings: []string{"login session database unavailable: " + err.Error()}}, nil
		}
		return LoggedInUsers{}, err
	}
	out := LoggedInUsers{Snapshot: snapshot(), Sessions: []LoginSession{}}
	for _, u := range users {
		started := int64(u.Started)
		out.Sessions = append(out.Sessions, LoginSession{
			Username: u.User, Terminal: u.Terminal, RemoteHost: u.Host, StartedUnix: &started})
	}
	sort.Slice(out.Sessions, func(i, j int) bool {
		a, b := out.Sessions[i], out.Sessions[j]
		if a.Username != b.Username {
			return a.Username < b.Username
		}
		return a.Terminal < b.Terminal
	})
	return out, nil
}
