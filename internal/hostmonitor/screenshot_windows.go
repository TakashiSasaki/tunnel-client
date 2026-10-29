//go:build windows

package hostmonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"runtime"
	"time"
	"unsafe"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/windows"
)

const (
	maxScreenshotPixels = 4 * 1024 * 1024
	// Base64 expands this to at most 8 MiB, leaving room for the tunnel's
	// envelope and MCP metadata within its default 10 MiB response limit.
	maxScreenshotPNGBytes = 6 * 1024 * 1024
)

var (
	errDesktopUnavailable          = errors.New("interactive desktop unavailable")
	screenshotSlot                 = make(chan struct{}, 1)
	screenUser32                   = windows.NewLazySystemDLL("user32.dll")
	screenGDI32                    = windows.NewLazySystemDLL("gdi32.dll")
	screenGetDC                    = screenUser32.NewProc("GetDC")
	screenReleaseDC                = screenUser32.NewProc("ReleaseDC")
	screenGetSystemMetrics         = screenUser32.NewProc("GetSystemMetrics")
	screenOpenInputDesktop         = screenUser32.NewProc("OpenInputDesktop")
	screenCloseDesktop             = screenUser32.NewProc("CloseDesktop")
	screenGetThreadDesktop         = screenUser32.NewProc("GetThreadDesktop")
	screenGetUserObjectInformation = screenUser32.NewProc("GetUserObjectInformationW")
	screenSetThreadDPI             = screenUser32.NewProc("SetThreadDpiAwarenessContext")
	screenCreateCompatibleDC       = screenGDI32.NewProc("CreateCompatibleDC")
	screenDeleteDC                 = screenGDI32.NewProc("DeleteDC")
	screenCreateDIBSection         = screenGDI32.NewProc("CreateDIBSection")
	screenDeleteObject             = screenGDI32.NewProc("DeleteObject")
	screenSelectObject             = screenGDI32.NewProc("SelectObject")
	screenStretchBlt               = screenGDI32.NewProc("StretchBlt")
	screenSetStretchBltMode        = screenGDI32.NewProc("SetStretchBltMode")
	screenGDIFlush                 = screenGDI32.NewProc("GdiFlush")
)

type ScreenshotArgs struct {
	Display   string `json:"display,omitempty" jsonschema:"primary (default) or all (the virtual desktop spanning all monitors)."`
	MaxWidth  int    `json:"max_width,omitempty" jsonschema:"Maximum image width; default 1280, allowed 1 through 4096. Aspect ratio is preserved; no upscaling."`
	MaxHeight int    `json:"max_height,omitempty" jsonschema:"Maximum image height; default 720, allowed 1 through 4096. Output is limited to 4194304 pixels."`
}

type ScreenshotInfo struct {
	Snapshot       Snapshot `json:"snapshot"`
	Display        string   `json:"display"`
	SourceX        int      `json:"source_x"`
	SourceY        int      `json:"source_y"`
	SourceWidth    int      `json:"source_width"`
	SourceHeight   int      `json:"source_height"`
	Width          int      `json:"width"`
	Height         int      `json:"height"`
	PNGBytes       int      `json:"png_bytes"`
	CursorIncluded bool     `json:"cursor_included"`
}

func registerPlatformTools(s *mcp.Server, timeout time.Duration) {
	no := false
	mcp.AddTool(s, &mcp.Tool{
		Name:        "screenshot",
		Description: "Windows only: capture the current session's visible desktop as an in-memory PNG image. Default is the primary screen, fitted within 1280x720. Set display=all for the combined desktop. No files are saved and no input is sent. Requires an accessible interactive desktop; service/locked/secure desktops may be unavailable. Cursor and protected video content are not captured.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &no, OpenWorldHint: &no},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args ScreenshotArgs) (*mcp.CallToolResult, ScreenshotInfo, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		data, info, err := captureScreenshot(ctx, args)
		if err != nil {
			return nil, ScreenshotInfo{}, err
		}
		metadata, err := json.Marshal(info)
		if err != nil {
			return nil, ScreenshotInfo{}, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{
			&mcp.TextContent{Text: string(metadata)},
			&mcp.ImageContent{Data: data, MIMEType: "image/png"},
		}}, info, nil
	})
}

func normalizeScreenshotArgs(args ScreenshotArgs) (ScreenshotArgs, error) {
	if args.Display == "" {
		args.Display = "primary"
	}
	if args.Display != "primary" && args.Display != "all" {
		return args, fmt.Errorf("display must be primary or all")
	}
	if args.MaxWidth == 0 {
		args.MaxWidth = 1280
	}
	if args.MaxHeight == 0 {
		args.MaxHeight = 720
	}
	if args.MaxWidth < 1 || args.MaxWidth > 4096 || args.MaxHeight < 1 || args.MaxHeight > 4096 {
		return args, fmt.Errorf("max_width and max_height must be between 1 and 4096")
	}
	return args, nil
}

func screenshotSize(sourceWidth, sourceHeight, maxWidth, maxHeight int) (int, int, error) {
	if sourceWidth < 1 || sourceHeight < 1 || sourceWidth > 1<<20 || sourceHeight > 1<<20 {
		return 0, 0, fmt.Errorf("invalid desktop dimensions")
	}
	scale := min(1.0, float64(maxWidth)/float64(sourceWidth), float64(maxHeight)/float64(sourceHeight))
	width, height := max(1, int(float64(sourceWidth)*scale)), max(1, int(float64(sourceHeight)*scale))
	if width*height > maxScreenshotPixels {
		return 0, 0, fmt.Errorf("screenshot exceeds 4194304 pixels; lower max_width or max_height")
	}
	return width, height, nil
}

// captureScreenshot keeps GDI handles, DIB storage and PNG encoding within one
// serialized operation. No screenshot bytes are written to disk or to logs.
func captureScreenshot(ctx context.Context, args ScreenshotArgs) ([]byte, ScreenshotInfo, error) {
	args, err := normalizeScreenshotArgs(args)
	if err != nil {
		return nil, ScreenshotInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, ScreenshotInfo{}, err
	}
	select {
	case screenshotSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ScreenshotInfo{}, ctx.Err()
	}
	defer func() { <-screenshotSlot }()
	if err := ctx.Err(); err != nil {
		return nil, ScreenshotInfo{}, err
	}
	// Desktop handles and DPI awareness are thread-scoped. Never change the
	// process's DPI mode, display settings, input desktop, cursor or focus.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ensureInteractiveDesktop(); err != nil {
		return nil, ScreenshotInfo{}, err
	}
	if err := screenSetThreadDPI.Find(); err != nil {
		return nil, ScreenshotInfo{}, fmt.Errorf("per-thread DPI awareness is unavailable: %w", err)
	}
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4.
	previous, _, _ := screenSetThreadDPI.Call(^uintptr(3))
	if previous == 0 {
		return nil, ScreenshotInfo{}, fmt.Errorf("cannot establish screenshot DPI context")
	}
	defer screenSetThreadDPI.Call(previous)
	x, y, width, height := 0, 0, screenMetric(0), screenMetric(1)
	if args.Display == "all" {
		x, y, width, height = screenMetric(76), screenMetric(77), screenMetric(78), screenMetric(79)
	}
	outWidth, outHeight, err := screenshotSize(width, height, args.MaxWidth, args.MaxHeight)
	if err != nil {
		return nil, ScreenshotInfo{}, err
	}
	info := ScreenshotInfo{Snapshot: snapshot(), Display: args.Display, SourceX: x, SourceY: y, SourceWidth: width, SourceHeight: height, Width: outWidth, Height: outHeight}
	sourceDC, _, _ := screenGetDC.Call(0)
	if sourceDC == 0 {
		return nil, ScreenshotInfo{}, fmt.Errorf("%w: GetDC failed", errDesktopUnavailable)
	}
	defer screenReleaseDC.Call(0, sourceDC)
	memoryDC, _, _ := screenCreateCompatibleDC.Call(sourceDC)
	if memoryDC == 0 {
		return nil, ScreenshotInfo{}, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer screenDeleteDC.Call(memoryDC)
	bitmapInfo := screenBitmapInfo{Header: screenBitmapInfoHeader{Size: uint32(unsafe.Sizeof(screenBitmapInfoHeader{})), Width: int32(outWidth), Height: -int32(outHeight), Planes: 1, BitCount: 32}}
	var pixels unsafe.Pointer
	bitmap, _, _ := screenCreateDIBSection.Call(sourceDC, uintptr(unsafe.Pointer(&bitmapInfo)), 0, uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if bitmap == 0 || pixels == nil {
		return nil, ScreenshotInfo{}, fmt.Errorf("CreateDIBSection failed")
	}
	defer screenDeleteObject.Call(bitmap)
	oldBitmap, _, _ := screenSelectObject.Call(memoryDC, bitmap)
	if oldBitmap == 0 || oldBitmap == ^uintptr(0) {
		return nil, ScreenshotInfo{}, fmt.Errorf("SelectObject failed")
	}
	defer screenSelectObject.Call(memoryDC, oldBitmap)
	// COLORONCOLOR changes only our memory DC and avoids expensive resampling.
	if previousMode, _, _ := screenSetStretchBltMode.Call(memoryDC, 3); previousMode == 0 {
		return nil, ScreenshotInfo{}, fmt.Errorf("SetStretchBltMode failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, ScreenshotInfo{}, err
	}
	const sourceCopyWithLayeredWindows = 0x00cc0020 | 0x40000000
	ok, _, _ := screenStretchBlt.Call(memoryDC, 0, 0, uintptr(outWidth), uintptr(outHeight), sourceDC, uintptr(x), uintptr(y), uintptr(width), uintptr(height), sourceCopyWithLayeredWindows)
	if ok == 0 {
		return nil, ScreenshotInfo{}, fmt.Errorf("desktop capture failed (StretchBlt)")
	}
	// Flush the GDI batch before CPU access to DIB memory, as required by GDI.
	if ok, _, _ := screenGDIFlush.Call(); ok == 0 {
		return nil, ScreenshotInfo{}, fmt.Errorf("GdiFlush failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, ScreenshotInfo{}, err
	}
	pix := unsafe.Slice((*byte)(pixels), outWidth*outHeight*4)
	bgraToRGBA(pix)
	img := &image.RGBA{Pix: pix, Stride: outWidth * 4, Rect: image.Rect(0, 0, outWidth, outHeight)}
	encoded := &screenshotPNGWriter{ctx: ctx}
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := encoder.Encode(encoded, img); err != nil {
		return nil, ScreenshotInfo{}, fmt.Errorf("encode screenshot PNG: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, ScreenshotInfo{}, err
	}
	info.PNGBytes = encoded.Len()
	return encoded.Bytes(), info, nil
}

type screenBitmapInfoHeader struct {
	Size            uint32
	Width           int32
	Height          int32
	Planes          uint16
	BitCount        uint16
	Compression     uint32
	SizeImage       uint32
	XPelsPerMeter   int32
	YPelsPerMeter   int32
	ColorsUsed      uint32
	ColorsImportant uint32
}

type screenBitmapInfo struct {
	Header screenBitmapInfoHeader
	Colors [1]uint32
}

func bgraToRGBA(pixels []byte) {
	for i := 0; i < len(pixels); i += 4 {
		pixels[i], pixels[i+2] = pixels[i+2], pixels[i]
		pixels[i+3] = 255
	}
}

type screenshotPNGWriter struct {
	bytes.Buffer
	ctx context.Context
}

func (w *screenshotPNGWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > maxScreenshotPNGBytes-w.Len() {
		return 0, fmt.Errorf("PNG exceeds 6 MiB; lower max_width or max_height")
	}
	return w.Buffer.Write(p)
}

func screenMetric(index int) int {
	v, _, _ := screenGetSystemMetrics.Call(uintptr(index))
	return int(int32(v))
}

func desktopName(handle uintptr) (string, error) {
	var name [512]uint16
	var needed uint32
	ok, _, _ := screenGetUserObjectInformation.Call(handle, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		return "", fmt.Errorf("cannot query desktop name")
	}
	return windows.UTF16ToString(name[:]), nil
}

func ensureInteractiveDesktop() error {
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil || sessionID == 0 {
		return fmt.Errorf("%w: no interactive user session", errDesktopUnavailable)
	}
	// DESKTOP_READOBJECTS only: never switch desktops or request write access.
	input, _, _ := screenOpenInputDesktop.Call(0, 0, 1)
	if input == 0 {
		return fmt.Errorf("%w: cannot read the input desktop", errDesktopUnavailable)
	}
	defer screenCloseDesktop.Call(input)
	thread, _, _ := screenGetThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	inputName, inputErr := desktopName(input)
	threadName, threadErr := desktopName(thread)
	if inputErr != nil || threadErr != nil || inputName == "" || inputName != threadName {
		return fmt.Errorf("%w: current thread is not on the visible desktop", errDesktopUnavailable)
	}
	return nil
}
