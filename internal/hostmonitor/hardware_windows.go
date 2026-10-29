//go:build windows

package hostmonitor

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
)

// Only fixed SELECT statements are used. No WMI methods, privilege changes,
// provider installation, device rescans or helper processes are requested.
var hardwareWMISlot = make(chan struct{}, 1)

func hardwareWMIQuery[T any](ctx context.Context, query, namespace string) ([]T, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case hardwareWMISlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	type result struct {
		rows []T
		err  error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-hardwareWMISlot }()
		rows := []T{}
		client := wmi.Client{NonePtrZero: true, PtrNil: true, AllowMissingFields: true}
		err := client.Query(query, &rows, nil, namespace)
		done <- result{rows: rows, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		return r.rows, r.err
	}
}

type windowsCPU struct {
	DeviceID                  string
	Name                      string
	Manufacturer              string
	NumberOfCores             *uint32
	NumberOfLogicalProcessors *uint32
	MaxClockSpeed             *uint32
}

func cpuInfo(ctx context.Context, _ EmptyArgs) (CPUInfo, error) {
	const source = "WMI:root/cimv2:Win32_Processor"
	rows, err := hardwareWMIQuery[windowsCPU](ctx, "SELECT DeviceID, Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor", "root/cimv2")
	if err != nil {
		return CPUInfo{}, err
	}
	out := CPUInfo{Snapshot: snapshot(), Architecture: runtime.GOARCH, Processors: []CPUProcessor{}, Sources: []ProbeStatus{availableProbe(source, len(rows))}}
	totalPhysical, totalLogical := 0, 0
	physicalKnown, logicalKnown := len(rows) > 0, len(rows) > 0
	for _, r := range rows {
		p := CPUProcessor{ID: r.DeviceID, Model: strings.TrimSpace(r.Name), Vendor: strings.TrimSpace(r.Manufacturer)}
		if r.NumberOfCores != nil {
			p.PhysicalCores = positiveInt(*r.NumberOfCores)
		}
		if r.NumberOfLogicalProcessors != nil {
			p.LogicalCPUs = positiveInt(*r.NumberOfLogicalProcessors)
		}
		if r.MaxClockSpeed != nil {
			p.MaxClockMHz = positiveMHz(float64(*r.MaxClockSpeed))
		}
		if p.PhysicalCores != nil {
			totalPhysical += *p.PhysicalCores
		} else {
			physicalKnown = false
		}
		if p.LogicalCPUs != nil {
			totalLogical += *p.LogicalCPUs
		} else {
			logicalKnown = false
		}
		out.Processors = append(out.Processors, p)
	}
	if physicalKnown {
		out.PhysicalCores = positiveInt(totalPhysical)
	}
	if logicalKnown {
		out.LogicalCPUs = positiveInt(totalLogical)
	}
	sort.Slice(out.Processors, func(i, j int) bool { return out.Processors[i].ID < out.Processors[j].ID })
	return out, nil
}

type windowsGPU struct{ DeviceID, Name, AdapterCompatibility, PNPDeviceID, DriverVersion, Status string }

func gpuInfo(ctx context.Context, _ EmptyArgs) (GPUInfo, error) {
	const source = "WMI:root/cimv2:Win32_VideoController"
	rows, err := hardwareWMIQuery[windowsGPU](ctx, "SELECT DeviceID, Name, AdapterCompatibility, PNPDeviceID, DriverVersion, Status FROM Win32_VideoController", "root/cimv2")
	out := GPUInfo{Snapshot: snapshot(), Devices: []GPU{}, Sources: []ProbeStatus{}}
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		out.Sources = append(out.Sources, unavailableProbe(source, err))
		return out, nil
	}
	for _, r := range rows {
		id := r.PNPDeviceID
		if id == "" {
			id = r.DeviceID
		}
		vendorID, deviceID := windowsHardwareIDs(id)
		out.Devices = append(out.Devices, GPU{ID: id, Name: r.Name, Vendor: r.AdapterCompatibility, VendorID: vendorID, DeviceID: deviceID, DriverVersion: r.DriverVersion, Status: r.Status, Source: source})
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].ID < out.Devices[j].ID })
	out.Sources = append(out.Sources, availableProbe(source, len(out.Devices)))
	return out, nil
}

type windowsDevice struct{ DeviceID, Name, Manufacturer, PNPClass, Service, Status string }

func hardwareDevices(ctx context.Context, _ string) (DeviceList, error) {
	const source = "WMI:root/cimv2:Win32_PnPEntity"
	rows, err := hardwareWMIQuery[windowsDevice](ctx, "SELECT DeviceID, Name, Manufacturer, PNPClass, Service, Status FROM Win32_PnPEntity WHERE Present = TRUE", "root/cimv2")
	out := DeviceList{Snapshot: snapshot(), Devices: []HardwareDevice{}, Sources: []ProbeStatus{}}
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		out.Sources = append(out.Sources, unavailableProbe(source, err))
		return out, nil
	}
	// Sort before bounding so pagination is repeatable for a stable inventory.
	sort.Slice(rows, func(i, j int) bool { return rows[i].DeviceID < rows[j].DeviceID })
	if len(rows) > maxHardwareRecords {
		out.Truncated = true
		rows = rows[:maxHardwareRecords]
	}
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		bus := strings.ToLower(strings.SplitN(r.DeviceID, "\\", 2)[0])
		if bus == "" {
			bus = "unknown"
		}
		vendorID, deviceID := windowsHardwareIDs(r.DeviceID)
		out.Devices = append(out.Devices, HardwareDevice{ID: r.DeviceID, Bus: bus, Category: deviceCategory(r.PNPClass), Name: r.Name,
			Vendor: r.Manufacturer, VendorID: vendorID, DeviceID: deviceID, Class: r.PNPClass, Driver: r.Service, Status: r.Status, Source: source})
	}
	out.Sources = append(out.Sources, availableProbe(source, len(out.Devices)))
	return out, nil
}

func windowsHardwareIDs(id string) (string, string) {
	id = strings.ToUpper(id)
	for _, tokens := range [][2]string{{"VEN_", "DEV_"}, {"VID_", "PID_"}} {
		a, b := "", ""
		for i, token := range tokens {
			at := strings.Index(id, token)
			if at < 0 || len(id) < at+len(token)+4 {
				continue
			}
			value := id[at+len(token) : at+len(token)+4]
			valid := true
			for _, c := range value {
				if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
					valid = false
				}
			}
			if valid {
				if i == 0 {
					a = strings.ToLower(value)
				} else {
					b = strings.ToLower(value)
				}
			}
		}
		if a != "" || b != "" {
			return a, b
		}
	}
	return "", ""
}

type windowsThermalZone struct {
	InstanceName       string
	CurrentTemperature *uint32
	Active             *bool
}
type windowsSensor struct {
	Identifier, Name, SensorType string
	Value                        *float32
}
type windowsNamespace struct{ Name string }

func temperatureWMIQuery[T any](ctx context.Context, query, namespace string) ([]T, error) {
	// One unsupported provider must not consume the entire tool budget and
	// discard successful readings from other sources. Native queries retain
	// the shared slot until they finish, even after this source's timeout.
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return hardwareWMIQuery[T](probeCtx, query, namespace)
}

func temperatures(ctx context.Context, _ EmptyArgs) (Temperatures, error) {
	out := Temperatures{Snapshot: snapshot(), Sensors: []Temperature{}, Sources: []ProbeStatus{}}
	const acpiSource = "WMI:root/wmi:MSAcpi_ThermalZoneTemperature"
	zones, err := temperatureWMIQuery[windowsThermalZone](ctx, "SELECT InstanceName, CurrentTemperature, Active FROM MSAcpi_ThermalZoneTemperature", "root/wmi")
	if err != nil {
		out.Sources = append(out.Sources, unavailableProbe(acpiSource, err))
	} else {
		before := len(out.Sensors)
		for _, z := range zones {
			if z.Active != nil && !*z.Active {
				continue
			}
			if z.CurrentTemperature == nil || *z.CurrentTemperature == 0 {
				addHardwareWarning(&out.Warnings, acpiSource+":"+z.InstanceName+": no valid temperature reading")
				continue
			}
			c := float64(*z.CurrentTemperature)/10 - 273.15
			if !validTemperature(c) {
				addHardwareWarning(&out.Warnings, acpiSource+":"+z.InstanceName+": invalid temperature")
				continue
			}
			if len(out.Sensors) >= 512 {
				out.Truncated = true
				break
			}
			out.Sensors = append(out.Sensors, Temperature{ID: z.InstanceName, Name: z.InstanceName, Kind: "thermal_zone", Celsius: c, Source: acpiSource})
		}
		out.Sources = append(out.Sources, availableProbe(acpiSource, len(out.Sensors)-before))
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	// Discover already-published namespaces only. This never starts or installs
	// LibreHardwareMonitor/OpenHardwareMonitor or asks them to enable sensors.
	namespaces, nsErr := temperatureWMIQuery[windowsNamespace](ctx, "SELECT Name FROM __NAMESPACE", "root")
	published := map[string]bool{}
	for _, ns := range namespaces {
		published[strings.ToLower(ns.Name)] = true
	}
	for _, name := range []string{"LibreHardwareMonitor", "OpenHardwareMonitor"} {
		source := "WMI:root/" + name + ":Sensor"
		if nsErr != nil {
			out.Sources = append(out.Sources, unavailableProbe(source, fmt.Errorf("namespace discovery: %w", nsErr)))
			continue
		}
		if !published[strings.ToLower(name)] {
			out.Sources = append(out.Sources, unavailableProbe(source, fmt.Errorf("no existing sensor namespace")))
			continue
		}
		rows, err := temperatureWMIQuery[windowsSensor](ctx, "SELECT Identifier, Name, SensorType, Value FROM Sensor WHERE SensorType = 'Temperature'", "root/"+name)
		if err != nil {
			out.Sources = append(out.Sources, unavailableProbe(source, err))
			continue
		}
		before := len(out.Sensors)
		for _, r := range rows {
			if r.Value == nil || !validTemperature(float64(*r.Value)) {
				addHardwareWarning(&out.Warnings, source+":"+r.Identifier+": no valid temperature reading")
				continue
			}
			if len(out.Sensors) >= 512 {
				out.Truncated = true
				break
			}
			out.Sensors = append(out.Sensors, Temperature{ID: r.Identifier, Name: r.Name, Kind: "temperature", Celsius: float64(*r.Value), Source: source})
		}
		out.Sources = append(out.Sources, availableProbe(source, len(out.Sensors)-before))
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	sort.Slice(out.Sensors, func(i, j int) bool {
		a, b := out.Sensors[i], out.Sensors[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.ID < b.ID
	})
	return out, nil
}
