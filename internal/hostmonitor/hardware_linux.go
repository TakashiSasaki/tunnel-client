// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build linux

package hostmonitor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v4/cpu"
)

func linuxSystemRoot(env, fallback string) string {
	if root := strings.TrimSpace(os.Getenv(env)); root != "" {
		return root
	}
	return fallback
}

func cpuInfo(ctx context.Context, _ EmptyArgs) (CPUInfo, error) {
	infos, err := cpu.InfoWithContext(ctx)
	if err != nil {
		return CPUInfo{}, err
	}
	return linuxCPUInfo(infos), nil
}

func linuxCPUInfo(infos []cpu.InfoStat) CPUInfo {
	source := filepath.Join(linuxSystemRoot("HOST_PROC", "/proc"), "cpuinfo")
	out := CPUInfo{Snapshot: snapshot(), Architecture: runtime.GOARCH, Processors: []CPUProcessor{}, Sources: []ProbeStatus{availableProbe(source, len(infos))}}
	type group struct {
		p             CPUProcessor
		cores         map[string]bool
		logical       int
		topologyKnown bool
	}
	groups := map[string]*group{}
	for _, info := range infos {
		id := info.PhysicalID
		if id == "" {
			id = "unknown"
		}
		g := groups[id]
		if g == nil {
			g = &group{p: CPUProcessor{ID: id, Model: info.ModelName, Vendor: info.VendorID, ReportedClockMHz: positiveMHz(info.Mhz)}, cores: map[string]bool{}, topologyKnown: info.PhysicalID != ""}
			groups[id] = g
		}
		g.logical++
		if info.CoreID == "" {
			g.topologyKnown = false
		} else {
			g.cores[info.CoreID] = true
		}
	}
	physical, totalLogical := 0, 0
	physicalKnown := len(groups) > 0
	for _, g := range groups {
		g.p.LogicalCPUs = positiveInt(g.logical)
		totalLogical += g.logical
		if g.topologyKnown {
			g.p.PhysicalCores = positiveInt(len(g.cores))
			physical += len(g.cores)
		} else {
			physicalKnown = false
		}
		out.Processors = append(out.Processors, g.p)
	}
	if physicalKnown {
		out.PhysicalCores = positiveInt(physical)
	} else {
		out.Warnings = append(out.Warnings, "physical CPU topology is not fully exposed; physical core count omitted")
	}
	out.LogicalCPUs = positiveInt(totalLogical)
	sort.Slice(out.Processors, func(i, j int) bool { return out.Processors[i].ID < out.Processors[j].ID })
	return out
}

func hardwareDevices(ctx context.Context, bus string) (DeviceList, error) {
	return sysfsDevices(ctx, linuxSystemRoot("HOST_SYS", "/sys"), bus)
}

func gpuInfo(ctx context.Context, _ EmptyArgs) (GPUInfo, error) {
	devices, err := hardwareDevices(ctx, "pci")
	if err != nil {
		return GPUInfo{}, err
	}
	out := GPUInfo{Snapshot: snapshot(), Devices: []GPU{}, Sources: devices.Sources, Warnings: devices.Warnings, Truncated: devices.Truncated}
	for _, d := range devices.Devices {
		if d.Category != "graphics" {
			continue
		}
		g := GPU{ID: d.ID, Name: d.Name, Vendor: d.Vendor, VendorID: d.VendorID, DeviceID: d.DeviceID, Driver: d.Driver, Source: d.Source}
		// An already-loaded NVIDIA driver may expose its model as a proc file.
		// Missing files are optional; no modules are loaded and no commands run.
		path := filepath.Join(linuxSystemRoot("HOST_PROC", "/proc"), "driver", "nvidia", "gpus", d.ID, "information")
		if data, err := readHardwareText(path); err == nil {
			for _, line := range strings.Split(data, "\n") {
				if model, ok := strings.CutPrefix(line, "Model:"); ok {
					g.Name = strings.TrimSpace(model)
					break
				}
			}
		}
		out.Devices = append(out.Devices, g)
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].ID < out.Devices[j].ID })
	return out, nil
}

func temperatures(ctx context.Context, _ EmptyArgs) (Temperatures, error) {
	return sysfsTemperatures(ctx, linuxSystemRoot("HOST_SYS", "/sys"))
}
