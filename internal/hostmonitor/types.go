// Package hostmonitor provides read-only host monitoring tools for an embedded MCP server.
package hostmonitor

// Snapshot identifies when and where a measurement was taken. Counters are
// cumulative snapshots, not rates, unless the tool explicitly samples an interval.
type Snapshot struct {
	ObservedAt string `json:"observed_at"`
	OS         string `json:"os"`
}

type HostInfo struct {
	Snapshot        Snapshot `json:"snapshot"`
	Hostname        string   `json:"hostname"`
	Architecture    string   `json:"architecture"`
	Platform        string   `json:"platform"`
	PlatformVersion string   `json:"platform_version"`
	UptimeSeconds   uint64   `json:"uptime_seconds"`
	LogicalCPUs     int      `json:"logical_cpus"`
}

type CPUUsage struct {
	Snapshot      Snapshot  `json:"snapshot"`
	SampleMS      int       `json:"sample_ms"`
	UsedPercent   float64   `json:"used_percent"`
	PerCPUPercent []float64 `json:"per_cpu_percent"`
}

type MemoryUsage struct {
	Snapshot       Snapshot `json:"snapshot"`
	TotalBytes     uint64   `json:"total_bytes"`
	AvailableBytes uint64   `json:"available_bytes"`
	UsedBytes      uint64   `json:"used_bytes"`
	UsedPercent    float64  `json:"used_percent"`
}

type SwapDevice struct {
	Name      string `json:"name"`
	UsedBytes uint64 `json:"used_bytes"`
	FreeBytes uint64 `json:"free_bytes"`
}

type SwapUsage struct {
	Snapshot    Snapshot     `json:"snapshot"`
	Kind        string       `json:"kind"`
	TotalBytes  uint64       `json:"total_bytes"`
	UsedBytes   uint64       `json:"used_bytes"`
	FreeBytes   uint64       `json:"free_bytes"`
	UsedPercent float64      `json:"used_percent"`
	Devices     []SwapDevice `json:"devices"`
}

type Volume struct {
	Device         string  `json:"device"`
	Mountpoint     string  `json:"mountpoint"`
	Filesystem     string  `json:"filesystem"`
	TotalBytes     uint64  `json:"total_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type DiskUsage struct {
	Snapshot Snapshot `json:"snapshot"`
	Volumes  []Volume `json:"volumes"`
	Warnings []string `json:"warnings,omitempty"`
}

type DiskCounter struct {
	Device     string `json:"device"`
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
}

type DiskIO struct {
	Snapshot Snapshot      `json:"snapshot"`
	Devices  []DiskCounter `json:"devices"`
}

type NetworkCounter struct {
	Name        string `json:"name"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_received"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_received"`
	ErrorsIn    uint64 `json:"errors_in"`
	ErrorsOut   uint64 `json:"errors_out"`
	DropsIn     uint64 `json:"drops_in"`
	DropsOut    uint64 `json:"drops_out"`
}

type NetworkIO struct {
	Snapshot   Snapshot         `json:"snapshot"`
	Interfaces []NetworkCounter `json:"interfaces"`
}

// Optional process fields are omitted when the process exits or the caller's
// existing permissions do not allow access. A zero measurement is not an error.
type Process struct {
	PID           int32    `json:"pid"`
	Name          string   `json:"name,omitempty"`
	ParentPID     *int32   `json:"parent_pid,omitempty"`
	Username      string   `json:"username,omitempty"`
	ResidentBytes *uint64  `json:"resident_bytes,omitempty"`
	CPUSeconds    *float64 `json:"cpu_seconds,omitempty"`
	Threads       *int32   `json:"threads,omitempty"`
	StartedUnixMS *int64   `json:"started_unix_ms,omitempty"`
	Unavailable   []string `json:"unavailable_fields,omitempty"`
}

type ProcessList struct {
	Snapshot   Snapshot  `json:"snapshot"`
	Total      int       `json:"total"`
	Offset     int       `json:"offset"`
	NextOffset int       `json:"next_offset"`
	HasMore    bool      `json:"has_more"`
	Processes  []Process `json:"processes"`
}

type LoginSession struct {
	Username    string  `json:"username"`
	Domain      string  `json:"domain,omitempty"`
	Terminal    string  `json:"terminal,omitempty"`
	RemoteHost  string  `json:"remote_host,omitempty"`
	State       string  `json:"state,omitempty"`
	SessionID   *uint32 `json:"session_id,omitempty"`
	StartedUnix *int64  `json:"started_unix,omitempty"`
}

type LoggedInUsers struct {
	Snapshot Snapshot       `json:"snapshot"`
	Sessions []LoginSession `json:"sessions"`
	Warnings []string       `json:"warnings,omitempty"`
}
