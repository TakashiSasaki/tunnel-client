// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostmonitor

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
)

const maxHardwareRecords = 4096

// ProbeStatus distinguishes a successful empty enumeration from a source which
// cannot be queried. Absence of a measurement is never represented by zero.
type ProbeStatus struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Count  int    `json:"count"`
	Detail string `json:"detail,omitempty"`
}

type CPUProcessor struct {
	ID               string   `json:"id"`
	Model            string   `json:"model,omitempty"`
	Vendor           string   `json:"vendor,omitempty"`
	PhysicalCores    *int     `json:"physical_cores,omitempty"`
	LogicalCPUs      *int     `json:"logical_cpus,omitempty"`
	ReportedClockMHz *float64 `json:"reported_clock_mhz,omitempty"`
	MaxClockMHz      *float64 `json:"max_clock_mhz,omitempty"`
}

type CPUInfo struct {
	Snapshot      Snapshot       `json:"snapshot"`
	Architecture  string         `json:"architecture"`
	Processors    []CPUProcessor `json:"processors"`
	PhysicalCores *int           `json:"physical_cores,omitempty"`
	LogicalCPUs   *int           `json:"logical_cpus,omitempty"`
	Sources       []ProbeStatus  `json:"sources"`
	Warnings      []string       `json:"warnings,omitempty"`
}

type GPU struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
	VendorID      string `json:"vendor_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	Driver        string `json:"driver,omitempty"`
	DriverVersion string `json:"driver_version,omitempty"`
	Status        string `json:"status,omitempty"`
	Source        string `json:"source"`
}

type GPUInfo struct {
	Snapshot  Snapshot      `json:"snapshot"`
	Devices   []GPU         `json:"devices"`
	Sources   []ProbeStatus `json:"sources"`
	Warnings  []string      `json:"warnings,omitempty"`
	Truncated bool          `json:"truncated"`
}

type HardwareDevice struct {
	ID       string `json:"id"`
	Bus      string `json:"bus"`
	Category string `json:"category"`
	Name     string `json:"name,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	VendorID string `json:"vendor_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Class    string `json:"class,omitempty"`
	Driver   string `json:"driver,omitempty"`
	Status   string `json:"status,omitempty"`
	Source   string `json:"source"`
}

type DeviceArgs struct {
	Bus    string `json:"bus,omitempty" jsonschema:"all (default), pci, or usb; filters the current OS inventory without probing hardware."`
	Offset int    `json:"offset,omitempty" jsonschema:"Zero-based offset into the current list sorted by bus and device ID."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum devices returned; default 100, maximum 500."`
}

type DeviceList struct {
	Snapshot   Snapshot         `json:"snapshot"`
	Total      int              `json:"total"`
	Offset     int              `json:"offset"`
	NextOffset int              `json:"next_offset"`
	HasMore    bool             `json:"has_more"`
	Truncated  bool             `json:"truncated"`
	Devices    []HardwareDevice `json:"devices"`
	Sources    []ProbeStatus    `json:"sources"`
	Warnings   []string         `json:"warnings,omitempty"`
}

type Temperature struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	Celsius float64 `json:"celsius"`
	Source  string  `json:"source"`
}

type Temperatures struct {
	Snapshot  Snapshot      `json:"snapshot"`
	Sensors   []Temperature `json:"sensors"`
	Sources   []ProbeStatus `json:"sources"`
	Warnings  []string      `json:"warnings,omitempty"`
	Truncated bool          `json:"truncated"`
}

func deviceList(ctx context.Context, args DeviceArgs) (DeviceList, error) {
	if args.Bus == "" {
		args.Bus = "all"
	}
	if args.Bus != "all" && args.Bus != "pci" && args.Bus != "usb" {
		return DeviceList{}, fmt.Errorf("bus must be all, pci or usb")
	}
	if args.Limit == 0 {
		args.Limit = 100
	}
	if args.Offset < 0 || args.Limit < 1 || args.Limit > 500 {
		return DeviceList{}, fmt.Errorf("offset must be nonnegative; limit must be between 1 and 500")
	}
	out, err := hardwareDevices(ctx, args.Bus)
	if err != nil {
		return DeviceList{}, err
	}
	filtered := make([]HardwareDevice, 0, len(out.Devices))
	for _, d := range out.Devices {
		if args.Bus == "all" || d.Bus == args.Bus {
			filtered = append(filtered, d)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Bus != filtered[j].Bus {
			return filtered[i].Bus < filtered[j].Bus
		}
		return filtered[i].ID < filtered[j].ID
	})
	out.Total = len(filtered)
	out.Offset = args.Offset
	start := min(args.Offset, len(filtered))
	end := start + min(args.Limit, len(filtered)-start)
	out.Devices = filtered[start:end]
	out.NextOffset = end
	out.HasMore = end < len(filtered)
	return out, nil
}

func positiveInt[T ~int | ~int32 | ~uint32](n T) *int {
	if n <= 0 {
		return nil
	}
	v := int(n)
	return &v
}

func positiveMHz(n float64) *float64 {
	if n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return nil
	}
	return &n
}

func availableProbe(source string, count int) ProbeStatus {
	return ProbeStatus{Source: source, Status: "available", Count: count}
}

func unavailableProbe(source string, err error) ProbeStatus {
	return ProbeStatus{Source: source, Status: "unavailable", Detail: err.Error()}
}

func addHardwareWarning(warnings *[]string, message string) {
	if len(*warnings) < 64 {
		*warnings = append(*warnings, message)
	}
}

func validTemperature(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value > -273.15 && value <= 1000
}

func deviceCategory(class string) string {
	switch strings.ToLower(class) {
	case "display":
		return "graphics"
	case "net":
		return "network"
	case "diskdrive", "hdc", "scsiadapter", "storage":
		return "storage"
	case "usb":
		return "usb"
	case "media", "audioendpoint":
		return "audio"
	case "processor":
		return "processor"
	default:
		return "other"
	}
}
