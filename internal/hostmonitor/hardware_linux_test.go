// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build linux

package hostmonitor

import (
	"testing"

	"github.com/shirou/gopsutil/v4/cpu"
)

func TestLinuxCPUInventoryCountsCoresWithinEachSocket(t *testing.T) {
	var records []cpu.InfoStat
	for _, socket := range []string{"0", "1"} {
		for _, core := range []string{"0", "1"} {
			for range 2 {
				records = append(records, cpu.InfoStat{PhysicalID: socket, CoreID: core, ModelName: "test CPU", VendorID: "test", Mhz: 2500})
			}
		}
	}
	out := linuxCPUInfo(records)
	if len(out.Processors) != 2 || out.PhysicalCores == nil || *out.PhysicalCores != 4 || out.LogicalCPUs == nil || *out.LogicalCPUs != 8 {
		t.Fatalf("logical threads were confused with physical cores: %+v", out)
	}
	for _, p := range out.Processors {
		if p.PhysicalCores == nil || *p.PhysicalCores != 2 || p.LogicalCPUs == nil || *p.LogicalCPUs != 4 {
			t.Fatalf("invalid socket counts: %+v", p)
		}
	}
	unknown := linuxCPUInfo([]cpu.InfoStat{{ModelName: "unknown topology"}, {ModelName: "unknown topology"}})
	if unknown.PhysicalCores != nil || unknown.LogicalCPUs == nil || *unknown.LogicalCPUs != 2 || len(unknown.Warnings) == 0 {
		t.Fatalf("unknown topology invented a physical core count: %+v", unknown)
	}
}
