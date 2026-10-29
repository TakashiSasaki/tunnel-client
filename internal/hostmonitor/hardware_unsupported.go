// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build !windows && !linux

package hostmonitor

import (
	"context"
	"fmt"
	"runtime"
)

func cpuInfo(context.Context, EmptyArgs) (CPUInfo, error) {
	return CPUInfo{}, fmt.Errorf("CPU inventory is supported on Windows and Linux")
}
func gpuInfo(context.Context, EmptyArgs) (GPUInfo, error) {
	return GPUInfo{Snapshot: snapshot(), Devices: []GPU{}, Sources: []ProbeStatus{unavailableProbe(runtime.GOOS, fmt.Errorf("GPU inventory is supported on Windows and Linux"))}}, nil
}
func hardwareDevices(context.Context, string) (DeviceList, error) {
	return DeviceList{Snapshot: snapshot(), Devices: []HardwareDevice{}, Sources: []ProbeStatus{unavailableProbe(runtime.GOOS, fmt.Errorf("device inventory is supported on Windows and Linux"))}}, nil
}
func temperatures(context.Context, EmptyArgs) (Temperatures, error) {
	return Temperatures{Snapshot: snapshot(), Sensors: []Temperature{}, Sources: []ProbeStatus{unavailableProbe(runtime.GOOS, fmt.Errorf("temperature inventory is supported on Windows and Linux"))}}, nil
}
