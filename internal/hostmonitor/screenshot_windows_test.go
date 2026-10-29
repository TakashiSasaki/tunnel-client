// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build windows

package hostmonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"runtime"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/windows"
)

func requireCaptureDesktop(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ensureInteractiveDesktop(); err != nil {
		if errors.Is(err, errDesktopUnavailable) {
			t.Skipf("desktop capture not available in this session: %v", err)
		}
		t.Fatal(err)
	}
}

func TestScreenshotMCPReturnsPNGAndMetadata(t *testing.T) {
	requireCaptureDesktop(t)
	session, ctx := connectMonitor(t)
	for _, display := range []string{"primary", "all"} {
		t.Run(display, func(t *testing.T) {
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "screenshot", Arguments: ScreenshotArgs{Display: display, MaxWidth: 320, MaxHeight: 180}})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsError {
				t.Fatalf("capture failed: %+v", result.Content)
			}
			raw, err := json.Marshal(result.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			var info ScreenshotInfo
			if err := json.Unmarshal(raw, &info); err != nil {
				t.Fatal(err)
			}
			if info.Width < 1 || info.Width > 320 || info.Height < 1 || info.Height > 180 || info.SourceWidth < info.Width || info.SourceHeight < info.Height || info.Display != display || info.CursorIncluded {
				t.Fatalf("invalid screenshot metadata: %+v", info)
			}
			images := 0
			for _, content := range result.Content {
				if img, ok := content.(*mcp.ImageContent); ok {
					images++
					if img.MIMEType != "image/png" || len(img.Data) != info.PNGBytes || len(img.Data) > maxScreenshotPNGBytes {
						t.Fatal("invalid PNG image content")
					}
					decoded, err := png.Decode(bytes.NewReader(img.Data))
					if err != nil {
						t.Fatal(err)
					}
					if decoded.Bounds().Dx() != info.Width || decoded.Bounds().Dy() != info.Height {
						t.Fatal("PNG dimensions differ from metadata")
					}
				}
			}
			if images != 1 {
				t.Fatalf("expected one image, got %d", images)
			}
			t.Logf("received %dx%d PNG (%d bytes), source %dx%d", info.Width, info.Height, info.PNGBytes, info.SourceWidth, info.SourceHeight)
		})
	}
}

func TestScreenshotRejectsInvalidInputAndCanceledRequests(t *testing.T) {
	for _, args := range []ScreenshotArgs{
		{Display: "window"}, {MaxWidth: -1}, {MaxWidth: 4097}, {MaxHeight: -1}, {MaxHeight: 4097},
	} {
		if _, _, err := captureScreenshot(context.Background(), args); err == nil {
			t.Fatalf("invalid capture arguments accepted: %+v", args)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := captureScreenshot(ctx, ScreenshotArgs{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	// Waiting for another capture must remain cancelable without touching GDI.
	screenshotSlot <- struct{}{}
	defer func() { <-screenshotSlot }()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := captureScreenshot(ctx, ScreenshotArgs{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture queue ignored timeout: %v", err)
	}
}

func TestScreenshotBoundsAndPixelConversion(t *testing.T) {
	for _, tc := range []struct{ sw, sh, mw, mh, w, h int }{
		{3840, 2160, 1280, 720, 1280, 720}, {1920, 1080, 320, 320, 320, 180},
		{1080, 1920, 320, 180, 101, 180}, {16, 8, 1280, 720, 16, 8},
	} {
		w, h, err := screenshotSize(tc.sw, tc.sh, tc.mw, tc.mh)
		if err != nil || w != tc.w || h != tc.h {
			t.Fatalf("size %+v: %dx%d, %v", tc, w, h, err)
		}
	}
	if _, _, err := screenshotSize(4096, 4096, 4096, 4096); err == nil {
		t.Fatal("unbounded bitmap accepted")
	}
	if _, _, err := screenshotSize(0, 1080, 320, 180); err == nil {
		t.Fatal("empty desktop accepted")
	}
	// A top-down 32-bit DIB has BGRA bytes; alpha may be zero. Verify both
	// channel order and PNG opacity without inspecting anyone's screen contents.
	pixels := []byte{0, 0, 255, 0, 255, 0, 0, 0}
	bgraToRGBA(pixels)
	encoded := &screenshotPNGWriter{ctx: context.Background()}
	if err := png.Encode(encoded, &image.RGBA{Pix: pixels, Stride: 4, Rect: image.Rect(0, 0, 1, 2)}); err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if color.RGBAModel.Convert(decoded.At(0, 0)) != (color.RGBA{R: 255, A: 255}) || color.RGBAModel.Convert(decoded.At(0, 1)) != (color.RGBA{B: 255, A: 255}) {
		t.Fatal("DIB channel order, row order or alpha was lost")
	}
	tooLarge := &screenshotPNGWriter{ctx: context.Background()}
	if _, err := tooLarge.Write(make([]byte, maxScreenshotPNGBytes+1)); err == nil || tooLarge.Len() != 0 {
		t.Fatal("oversized PNG output was buffered")
	}
}

func TestScreenshotRestoresThreadDPIAndReleasesGDI(t *testing.T) {
	requireCaptureDesktop(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	getDPI := screenUser32.NewProc("GetThreadDpiAwarenessContext")
	getResources := screenUser32.NewProc("GetGuiResources")
	previous, _, _ := getDPI.Call()
	before, _, _ := getResources.Call(uintptr(windows.CurrentProcess()), 0)
	for range 3 {
		if _, _, err := captureScreenshot(context.Background(), ScreenshotArgs{MaxWidth: 32, MaxHeight: 32}); err != nil {
			t.Fatal(err)
		}
	}
	afterDPI, _, _ := getDPI.Call()
	afterResources, _, _ := getResources.Call(uintptr(windows.CurrentProcess()), 0)
	if previous != afterDPI {
		t.Fatal("capture changed the caller's thread DPI context")
	}
	if afterResources != before {
		t.Fatalf("GDI objects leaked: before=%d after=%d", before, afterResources)
	}
}
