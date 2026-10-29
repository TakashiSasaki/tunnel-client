// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build windows

package hostmonitor

import "testing"

func TestWindowsDeviceIDsDoNotInventVendorInformation(t *testing.T) {
	for _, tc := range []struct{ id, vendor, device string }{
		{`PCI\VEN_10DE&DEV_2684&SUBSYS_0000`, "10de", "2684"},
		{`USB\VID_046D&PID_C534\instance`, "046d", "c534"},
		{`ROOT\UNKNOWN`, "", ""}, {`PCI\VEN_NOPE&DEV_1234`, "", "1234"},
	} {
		a, b := windowsHardwareIDs(tc.id)
		if a != tc.vendor || b != tc.device {
			t.Fatalf("%s: %s:%s", tc.id, a, b)
		}
	}
}
