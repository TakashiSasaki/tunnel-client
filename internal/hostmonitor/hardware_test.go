// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostmonitor

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func writeHardwareFixture(t *testing.T, root, relative, value string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSysfsTemperatureReadingsKeepRealZeroAndReportFailures(t *testing.T) {
	root := t.TempDir()
	for path, value := range map[string]string{
		"class/hwmon/hwmon0/name":               "coretemp\n",
		"class/hwmon/hwmon0/temp1_input":        "42000\n",
		"class/hwmon/hwmon0/temp1_label":        "Package id 0\n",
		"class/hwmon/hwmon0/temp2_input":        "0\n",
		"class/hwmon/hwmon0/temp2_label":        "Real zero\n",
		"class/hwmon/hwmon0/temp3_input":        "not available",
		"class/hwmon/hwmon0/temp4_input":        "-274000",
		"class/hwmon/hwmon0/temp5_input":        "55000",
		"class/hwmon/hwmon0/temp5_fault":        "1",
		"class/hwmon/hwmon0/temp6_input":        "55000",
		"class/hwmon/hwmon0/temp6_enable":       "0",
		"class/hwmon/hwmon1/device/name":        "legacy_chip",
		"class/hwmon/hwmon1/device/temp1_input": "31000",
		"class/thermal/thermal_zone0/type":      "acpitz",
		"class/thermal/thermal_zone0/temp":      "30000",
	} {
		writeHardwareFixture(t, root, path, value)
	}
	out, err := sysfsTemperatures(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Sensors) != 4 || len(out.Sources) != 2 || len(out.Warnings) != 4 {
		t.Fatalf("unexpected partial readings: %+v", out)
	}
	zeroFound := false
	for _, s := range out.Sensors {
		if s.Name == "coretemp / Real zero" {
			zeroFound = true
			if s.Celsius != 0 {
				t.Fatal("real zero Celsius was changed")
			}
		}
		if s.Source == "" || s.Name == "" || !validTemperature(s.Celsius) {
			t.Fatalf("invalid sensor: %+v", s)
		}
	}
	if !zeroFound {
		t.Fatal("valid zero Celsius was discarded")
	}
	// Read-only attributes used to suppress unavailable sensors must stay intact.
	if value, _ := readHardwareText(filepath.Join(root, "class", "hwmon", "hwmon0", "temp6_enable")); value != "0" {
		t.Fatal("disabled sensor was modified")
	}
	missing, err := sysfsTemperatures(context.Background(), t.TempDir())
	if err != nil || missing.Sensors == nil || len(missing.Sensors) != 0 || len(missing.Sources) != 2 {
		t.Fatalf("missing sources must produce an explicit empty result: %+v %v", missing, err)
	}
	for _, s := range missing.Sources {
		if s.Status != "unavailable" || s.Detail == "" {
			t.Fatalf("missing source treated as available: %+v", s)
		}
	}
}

func TestSysfsDeviceInventoryUsesOnlyExistingAttributes(t *testing.T) {
	root := t.TempDir()
	for path, value := range map[string]string{
		"bus/pci/devices/gpu0/vendor":          "0x10de",
		"bus/pci/devices/gpu0/device":          "0x2684",
		"bus/pci/devices/gpu0/class":           "0x030000",
		"bus/pci/devices/net0/vendor":          "0x8086",
		"bus/pci/devices/net0/device":          "0x100e",
		"bus/pci/devices/net0/class":           "0x020000",
		"bus/pci/devices/unknown0/vendor":      "0x8086",
		"bus/pci/devices/unknown0/device":      "0x1234",
		"bus/pci/devices/broken0/vendor":       "not hex",
		"bus/pci/devices/broken0/device":       "0x1234",
		"bus/usb/devices/1-1/idVendor":         "046d",
		"bus/usb/devices/1-1/idProduct":        "c534",
		"bus/usb/devices/1-1/manufacturer":     "Logitech",
		"bus/usb/devices/1-1/product":          "USB receiver",
		"bus/usb/devices/1-1/bDeviceClass":     "00",
		"bus/usb/devices/1-1:interface/unused": "interface-only",
	} {
		// Colons in sysfs interface names are not legal on the Windows fixture host.
		path = strings.ReplaceAll(path, ":interface", "_interface")
		writeHardwareFixture(t, root, path, value)
	}
	out, err := sysfsDevices(context.Background(), root, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Devices) != 4 || len(out.Sources) != 2 || len(out.Warnings) < 2 {
		t.Fatalf("unexpected inventory: %+v", out)
	}
	graphics, network, usb, unknown := false, false, false, false
	for _, d := range out.Devices {
		switch d.ID {
		case "gpu0":
			graphics = d.Category == "graphics" && d.VendorID == "10de" && d.Vendor == "NVIDIA"
		case "net0":
			network = d.Category == "network"
		case "1-1":
			usb = d.Bus == "usb" && d.Name == "USB receiver"
		case "unknown0":
			unknown = d.Category == "other" && d.Class == ""
		}
	}
	if !graphics || !network || !usb || !unknown {
		t.Fatalf("device categories were lost: %+v", out.Devices)
	}
	filtered, err := sysfsDevices(context.Background(), root, "pci")
	if err != nil || len(filtered.Devices) != 3 || len(filtered.Sources) != 1 {
		t.Fatalf("PCI filter: %+v %v", filtered, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sysfsDevices(ctx, root, "all"); err == nil {
		t.Fatal("device inventory ignored cancellation")
	}
	if _, err := sysfsTemperatures(ctx, root); err == nil {
		t.Fatal("temperature inventory ignored cancellation")
	}
}

func TestHardwareToolsReturnHostDataOverMCP(t *testing.T) {
	session, ctx := connectMonitor(t)
	cpu := readTool[CPUInfo](t, session, ctx, "cpu_info", EmptyArgs{})
	if len(cpu.Processors) == 0 || cpu.LogicalCPUs == nil || *cpu.LogicalCPUs < 1 || len(cpu.Sources) == 0 {
		t.Fatalf("invalid CPU inventory: %+v", cpu)
	}
	gpu := readTool[GPUInfo](t, session, ctx, "gpu_info", EmptyArgs{})
	if gpu.Devices == nil || len(gpu.Sources) == 0 {
		t.Fatalf("GPU enumeration lost source availability: %+v", gpu)
	}
	devices := readTool[DeviceList](t, session, ctx, "device_list", DeviceArgs{Limit: 3})
	if devices.Devices == nil || len(devices.Devices) > 3 || len(devices.Sources) == 0 || devices.NextOffset != len(devices.Devices) {
		t.Fatalf("unbounded device inventory: %+v", devices)
	}
	for i := 1; i < len(devices.Devices); i++ {
		a, b := devices.Devices[i-1], devices.Devices[i]
		if a.Bus > b.Bus || a.Bus == b.Bus && a.ID > b.ID {
			t.Fatal("device page was not sorted")
		}
	}
	usb := readTool[DeviceList](t, session, ctx, "device_list", DeviceArgs{Bus: "usb", Limit: 3})
	for _, d := range usb.Devices {
		if d.Bus != "usb" {
			t.Fatal("USB filter leaked another bus")
		}
	}
	pastEnd := readTool[DeviceList](t, session, ctx, "device_list", DeviceArgs{Offset: 1000000000})
	if len(pastEnd.Devices) != 0 || pastEnd.HasMore {
		t.Fatal("invalid end-of-list page")
	}
	temps := readTool[Temperatures](t, session, ctx, "temperatures", EmptyArgs{})
	if temps.Sensors == nil || len(temps.Sources) == 0 {
		t.Fatalf("temperature sources missing: %+v", temps)
	}
	for _, sensor := range temps.Sensors {
		if sensor.ID == "" || sensor.Source == "" || !validTemperature(sensor.Celsius) {
			t.Fatalf("invalid temperature: %+v", sensor)
		}
	}
	t.Logf("CPU packages=%d, GPU/video controllers=%d, OS devices=%d, temperature readings=%d", len(cpu.Processors), len(gpu.Devices), devices.Total, len(temps.Sensors))
	for _, source := range temps.Sources {
		t.Logf("temperature source %s: %s (%d readings)", source.Source, source.Status, source.Count)
	}
	for _, args := range []DeviceArgs{{Limit: 501}, {Offset: -1}, {Bus: "arbitrary"}} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "device_list", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatalf("accepted unbounded device request: %+v", args)
		}
	}
}

func TestMissingTemperatureIsNotZero(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), -273.15, 1001} {
		if validTemperature(value) {
			t.Fatalf("invalid temperature accepted: %v", value)
		}
	}
	if !validTemperature(0) || !validTemperature(-20) {
		t.Fatal("valid freezing temperatures rejected")
	}
	result := Temperatures{Sensors: []Temperature{}, Sources: []ProbeStatus{unavailableProbe("test", os.ErrPermission)}}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "celsius") || !strings.Contains(string(data), `"sensors":[]`) {
		t.Fatal("missing source invented a numeric temperature")
	}
}
