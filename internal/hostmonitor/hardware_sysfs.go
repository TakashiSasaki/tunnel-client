package hostmonitor

// These parsers read only explicit informational sysfs attributes. They are
// platform-independent so Linux parsing can be exercised with fixtures on Windows.
import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func readHardwareText(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 {
		return "", fmt.Errorf("hardware attribute exceeds 4096 bytes")
	}
	return strings.TrimSpace(string(raw)), nil
}

func optionalHardwareText(path string) string { value, _ := readHardwareText(path); return value }

func canonicalHex(raw string, bits int) (string, error) {
	raw = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "0x")
	v, err := strconv.ParseUint(raw, 16, bits)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*x", bits/4, v), nil
}

func pciCategory(class string) string {
	if len(class) < 2 {
		return "other"
	}
	switch class[:2] {
	case "01":
		return "storage"
	case "02":
		return "network"
	case "03":
		return "graphics"
	case "04":
		return "audio_multimedia"
	case "0c":
		if strings.HasPrefix(class, "0c03") {
			return "usb"
		}
	}
	return "other"
}

func pciVendorName(id string) string {
	return map[string]string{"10de": "NVIDIA", "1002": "AMD", "8086": "Intel", "1af4": "Red Hat/Virtio", "15ad": "VMware"}[id]
}

func sysfsDevices(ctx context.Context, root, bus string) (DeviceList, error) {
	out := DeviceList{Snapshot: snapshot(), Devices: []HardwareDevice{}, Sources: []ProbeStatus{}}
	for _, kind := range []string{"pci", "usb"} {
		if bus != "all" && bus != kind {
			continue
		}
		dir := filepath.Join(root, "bus", kind, "devices")
		entries, err := os.ReadDir(dir)
		if err != nil {
			out.Sources = append(out.Sources, unavailableProbe(dir, err))
			continue
		}
		before := len(out.Devices)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if len(out.Devices) >= maxHardwareRecords {
				out.Truncated = true
				break
			}
			path := filepath.Join(dir, entry.Name())
			vendorAttr, deviceAttr := "vendor", "device"
			if kind == "usb" {
				vendorAttr, deviceAttr = "idVendor", "idProduct"
			}
			vendorRaw, err := readHardwareText(filepath.Join(path, vendorAttr))
			// USB interface entries have no device IDs; the parent USB device is
			// enumerated separately. Do not turn these into duplicate devices.
			if kind == "usb" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				addHardwareWarning(&out.Warnings, path+": "+err.Error())
				continue
			}
			deviceRaw, err := readHardwareText(filepath.Join(path, deviceAttr))
			if err != nil {
				addHardwareWarning(&out.Warnings, path+": "+err.Error())
				continue
			}
			vendorID, verr := canonicalHex(vendorRaw, 16)
			deviceID, derr := canonicalHex(deviceRaw, 16)
			if verr != nil || derr != nil {
				addHardwareWarning(&out.Warnings, path+": invalid vendor/device IDs")
				continue
			}
			d := HardwareDevice{ID: entry.Name(), Bus: kind, Category: "usb", VendorID: vendorID, DeviceID: deviceID, Source: path}
			if kind == "pci" {
				d.Category = "other"
				d.Vendor = pciVendorName(vendorID)
				classRaw, err := readHardwareText(filepath.Join(path, "class"))
				if err != nil {
					addHardwareWarning(&out.Warnings, path+" class: "+err.Error())
				} else {
					class, err := canonicalHex(classRaw, 24)
					if err != nil {
						addHardwareWarning(&out.Warnings, path+": invalid PCI class")
					} else {
						d.Class = class
						d.Category = pciCategory(class)
					}
				}
				d.Name = optionalHardwareText(filepath.Join(path, "label"))
			} else {
				d.Vendor = optionalHardwareText(filepath.Join(path, "manufacturer"))
				d.Name = optionalHardwareText(filepath.Join(path, "product"))
				d.Class = optionalHardwareText(filepath.Join(path, "bDeviceClass"))
			}
			if d.Name == "" {
				d.Name = fmt.Sprintf("%s device %s:%s", strings.ToUpper(kind), vendorID, deviceID)
			}
			if driver, err := os.Readlink(filepath.Join(path, "driver")); err == nil {
				d.Driver = filepath.Base(driver)
			}
			out.Devices = append(out.Devices, d)
		}
		out.Sources = append(out.Sources, availableProbe(dir, len(out.Devices)-before))
	}
	return out, nil
}

func sysfsTemperatures(ctx context.Context, root string) (Temperatures, error) {
	out := Temperatures{Snapshot: snapshot(), Sensors: []Temperature{}, Sources: []ProbeStatus{}}
	hwmonRoot := filepath.Join(root, "class", "hwmon")
	entries, err := os.ReadDir(hwmonRoot)
	if err != nil {
		out.Sources = append(out.Sources, unavailableProbe(hwmonRoot, err))
	} else {
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			path := filepath.Join(hwmonRoot, entry.Name())
			files, err := filepath.Glob(filepath.Join(path, "temp*_input"))
			if err != nil {
				return out, err
			}
			if len(files) == 0 {
				files, err = filepath.Glob(filepath.Join(path, "device", "temp*_input"))
				if err != nil {
					return out, err
				}
			}
			for _, file := range files {
				if err := ctx.Err(); err != nil {
					return out, err
				}
				base := strings.TrimSuffix(file, "_input")
				// Fault/enable attributes are only read. Never enable or reset a sensor.
				if optionalHardwareText(base+"_fault") == "1" {
					addHardwareWarning(&out.Warnings, file+": sensor reports a fault")
					continue
				}
				if optionalHardwareText(base+"_enable") == "0" {
					addHardwareWarning(&out.Warnings, file+": sensor is disabled")
					continue
				}
				chip := optionalHardwareText(filepath.Join(filepath.Dir(file), "name"))
				if chip == "" {
					chip = entry.Name()
				}
				label := optionalHardwareText(base + "_label")
				if label == "" {
					label = filepath.Base(base)
				}
				appendSysfsTemperature(&out, file, chip+" / "+label, "hwmon")
			}
		}
		out.Sources = append(out.Sources, availableProbe(hwmonRoot, len(out.Sensors)))
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	thermalRoot := filepath.Join(root, "class", "thermal")
	entries, err = os.ReadDir(thermalRoot)
	if err != nil {
		out.Sources = append(out.Sources, unavailableProbe(thermalRoot, err))
	} else {
		before := len(out.Sensors)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if !strings.HasPrefix(entry.Name(), "thermal_zone") {
				continue
			}
			path := filepath.Join(thermalRoot, entry.Name())
			label := optionalHardwareText(filepath.Join(path, "type"))
			if label == "" {
				label = entry.Name()
			}
			appendSysfsTemperature(&out, filepath.Join(path, "temp"), label, "thermal_zone")
		}
		out.Sources = append(out.Sources, availableProbe(thermalRoot, len(out.Sensors)-before))
	}
	sort.Slice(out.Sensors, func(i, j int) bool { return out.Sensors[i].Source < out.Sensors[j].Source })
	return out, nil
}

func appendSysfsTemperature(out *Temperatures, path, label, kind string) {
	if len(out.Sensors) >= 512 {
		out.Truncated = true
		return
	}
	raw, err := readHardwareText(path)
	if err != nil {
		addHardwareWarning(&out.Warnings, path+": "+err.Error())
		return
	}
	milli, err := strconv.ParseInt(raw, 10, 64)
	celsius := float64(milli) / 1000
	if err != nil || !validTemperature(celsius) {
		addHardwareWarning(&out.Warnings, path+": invalid temperature reading")
		return
	}
	out.Sensors = append(out.Sensors, Temperature{ID: path, Name: label, Kind: kind, Celsius: celsius, Source: path})
}
