// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build windows

package hostmonitor

// Do not import gopsutil/host, /process or /disk on Windows. Their dependency
// initializers enable SeDebugPrivilege or write a disk-counter registry value.
// These adapters use only query access and never enable privileges/counters.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
)

var (
	wtsQuerySessionInformation = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQuerySessionInformationW")
	getProcessMemoryInfo       = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	// WMI calls cannot be forcibly canceled. Keep the slot until the OS call
	// actually finishes, even if its caller times out, to bound background work.
	diskQuerySlot = make(chan struct{}, 1)
)

func hostInfo(ctx context.Context, _ EmptyArgs) (HostInfo, error) {
	if err := ctx.Err(); err != nil {
		return HostInfo{}, err
	}
	name, err := os.Hostname()
	if err != nil {
		return HostInfo{}, err
	}
	v := windows.RtlGetVersion()
	return HostInfo{Snapshot: snapshot(), Hostname: name, Architecture: runtime.GOARCH,
		Platform: "windows", PlatformVersion: fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber),
		UptimeSeconds: uint64(windows.DurationSinceBoot() / time.Second), LogicalCPUs: runtime.NumCPU()}, nil
}

func localDrives(ctx context.Context) ([]string, error) {
	bits, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for i := 0; i < 26; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if bits&(1<<i) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+i)
		ptr, _ := windows.UTF16PtrFromString(root)
		kind := windows.GetDriveType(ptr)
		// Avoid remote network shares and empty optical/removable drives.
		if kind == windows.DRIVE_FIXED || kind == windows.DRIVE_RAMDISK {
			out = append(out, root)
		}
	}
	return out, nil
}

func diskUsage(ctx context.Context, _ EmptyArgs) (DiskUsage, error) {
	roots, err := localDrives(ctx)
	if err != nil {
		return DiskUsage{}, err
	}
	out := DiskUsage{Snapshot: snapshot(), Volumes: []Volume{}}
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return DiskUsage{}, err
		}
		ptr, _ := windows.UTF16PtrFromString(root)
		var available, total, free uint64
		if err := windows.GetDiskFreeSpaceEx(ptr, &available, &total, &free); err != nil {
			out.Warnings = append(out.Warnings, root+": "+err.Error())
			continue
		}
		var fs [261]uint16
		if err := windows.GetVolumeInformation(ptr, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
			out.Warnings = append(out.Warnings, root+" filesystem: "+err.Error())
		}
		used := total - min(free, total)
		var percent float64
		if total > 0 {
			percent = 100 * float64(used) / float64(total)
		}
		out.Volumes = append(out.Volumes, Volume{Device: root[:2], Mountpoint: root, Filesystem: windows.UTF16ToString(fs[:]),
			TotalBytes: total, FreeBytes: free, AvailableBytes: available, UsedBytes: used, UsedPercent: percent})
	}
	return out, nil
}

type rawPhysicalDisk struct {
	Name                 string
	DiskReadBytesPerSec  uint64
	DiskWriteBytesPerSec uint64
	DiskReadsPerSec      uint64
	DiskWritesPerSec     uint64
}

func diskIO(ctx context.Context, _ EmptyArgs) (DiskIO, error) {
	select {
	case diskQuerySlot <- struct{}{}:
	case <-ctx.Done():
		return DiskIO{}, ctx.Err()
	}
	type queryResult struct {
		rows []rawPhysicalDisk
		err  error
	}
	done := make(chan queryResult, 1)
	go func() {
		defer func() { <-diskQuerySlot }()
		var rows []rawPhysicalDisk
		// PerfRawData stores cumulative numerators despite the PerSec names.
		// This is a fixed SELECT: no WMI methods, shell commands or counter setup.
		err := wmi.Query("SELECT Name, DiskReadBytesPerSec, DiskWriteBytesPerSec, DiskReadsPerSec, DiskWritesPerSec FROM Win32_PerfRawData_PerfDisk_PhysicalDisk", &rows)
		done <- queryResult{rows: rows, err: err}
	}()
	select {
	case <-ctx.Done():
		return DiskIO{}, ctx.Err()
	case result := <-done:
		if result.err != nil {
			return DiskIO{}, fmt.Errorf("read existing disk performance counters: %w", result.err)
		}
		out := DiskIO{Snapshot: snapshot(), Devices: []DiskCounter{}}
		for _, row := range result.rows {
			if row.Name == "_Total" {
				continue
			}
			out.Devices = append(out.Devices, DiskCounter{Device: row.Name, ReadBytes: row.DiskReadBytesPerSec,
				WriteBytes: row.DiskWriteBytesPerSec, ReadCount: row.DiskReadsPerSec, WriteCount: row.DiskWritesPerSec})
		}
		if len(out.Devices) == 0 {
			return DiskIO{}, fmt.Errorf("no disk performance counters available; monitoring does not enable them")
		}
		sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].Device < out.Devices[j].Device })
		return out, nil
	}
}

func processEntries(ctx context.Context) ([]Process, error) {
	snapshotHandle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshotHandle)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(snapshotHandle, &entry)
	out := []Process{}
	for err == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parent, threads := int32(entry.ParentProcessID), int32(entry.Threads)
		out = append(out, Process{PID: int32(entry.ProcessID), Name: windows.UTF16ToString(entry.ExeFile[:]), ParentPID: &parent, Threads: &threads})
		err = windows.Process32Next(snapshotHandle, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return out, nil
}

// PROCESS_MEMORY_COUNTERS: SIZE_T fields match the native pointer width.
type processMemoryCounters struct {
	Size                       uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func processDetails(ctx context.Context, out Process) Process {
	if ctx.Err() != nil {
		out.Unavailable = append(out.Unavailable, "details: "+ctx.Err().Error())
		return out
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(out.PID))
	if err != nil {
		out.Unavailable = append(out.Unavailable, "username,resident_bytes,cpu_seconds,started_unix_ms: "+err.Error())
		return out
	}
	defer windows.CloseHandle(handle)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err == nil {
		started := created.Nanoseconds() / int64(time.Millisecond)
		seconds := float64(uint64(kernel.HighDateTime)<<32|uint64(kernel.LowDateTime))/1e7 + float64(uint64(user.HighDateTime)<<32|uint64(user.LowDateTime))/1e7
		out.StartedUnixMS = &started
		out.CPUSeconds = &seconds
	} else {
		out.Unavailable = append(out.Unavailable, "cpu_seconds,started_unix_ms: "+err.Error())
	}
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if user, err := token.GetTokenUser(); err == nil {
			account, domain, _, err := user.User.Sid.LookupAccount("")
			if err == nil {
				out.Username = account
				if domain != "" {
					out.Username = domain + "\\" + account
				}
			} else {
				out.Unavailable = append(out.Unavailable, "username: "+err.Error())
			}
		} else {
			out.Unavailable = append(out.Unavailable, "username: "+err.Error())
		}
	} else {
		out.Unavailable = append(out.Unavailable, "username: "+err.Error())
	}
	counters := processMemoryCounters{Size: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	ok, _, memoryErr := getProcessMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
	if ok != 0 {
		rss := uint64(counters.WorkingSetSize)
		out.ResidentBytes = &rss
	} else {
		out.Unavailable = append(out.Unavailable, "resident_bytes: "+memoryErr.Error())
	}
	return out
}

func sessionString(sessionID, class uint32) (string, error) {
	var buffer *uint16
	var size uint32
	ok, _, err := wtsQuerySessionInformation.Call(0, uintptr(sessionID), uintptr(class), uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		if err == syscall.Errno(0) {
			err = windows.ERROR_INVALID_DATA
		}
		return "", err
	}
	if buffer == nil {
		return "", nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	if size%2 != 0 || size > 1<<20 {
		return "", fmt.Errorf("invalid WTS string buffer size")
	}
	return windows.UTF16ToString(unsafe.Slice(buffer, int(size/2))), nil
}

func loggedInUsers(ctx context.Context, _ EmptyArgs) (LoggedInUsers, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return LoggedInUsers{}, err
	}
	if sessions != nil {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	}
	out := LoggedInUsers{Snapshot: snapshot(), Sessions: []LoginSession{}}
	if count > 1<<20 || (sessions == nil && count != 0) {
		return out, fmt.Errorf("invalid WTS session count")
	}
	states := []string{"active", "connected", "connect_query", "shadow", "disconnected", "idle", "listen", "reset", "down", "init"}
	for _, session := range unsafe.Slice(sessions, int(count)) {
		if err := ctx.Err(); err != nil {
			return LoggedInUsers{}, err
		}
		// WTSUserName=5, WTSDomainName=7. Empty usernames are service/listener sessions.
		username, err := sessionString(session.SessionID, 5)
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("session %d username: %s", session.SessionID, err))
			continue
		}
		if username == "" {
			continue
		}
		domain, err := sessionString(session.SessionID, 7)
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("session %d domain: %s", session.SessionID, err))
		}
		state := "unknown"
		if int(session.State) < len(states) {
			state = states[session.State]
		}
		id := session.SessionID
		out.Sessions = append(out.Sessions, LoginSession{Username: username, Domain: domain, State: state, SessionID: &id, Terminal: windows.UTF16PtrToString(session.WindowStationName)})
	}
	sort.Slice(out.Sessions, func(i, j int) bool { return *out.Sessions[i].SessionID < *out.Sessions[j].SessionID })
	return out, nil
}
