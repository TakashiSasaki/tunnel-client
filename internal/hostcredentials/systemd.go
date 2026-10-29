// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const systemdCredentialName = "host-monitor.credentials"

// Kept platform-independent to test the helper protocol without a Linux host.
type systemdEncryption struct {
	run func(context.Context, []string, []byte) ([]byte, error)
}

func (systemdEncryption) Name() string { return "systemd-user" }

func (s systemdEncryption) Check(ctx context.Context) error {
	data, err := s.run(ctx, []string{"--version"}, nil)
	if err != nil {
		return fmt.Errorf("%w: systemd-creds is required", ErrUnavailable)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 || fields[0] != "systemd" {
		return fmt.Errorf("%w: cannot identify systemd-creds version", ErrUnavailable)
	}
	version, err := strconv.Atoi(fields[1])
	if err != nil || version < 256 {
		return fmt.Errorf("%w: systemd 256 or newer is required for per-user encryption", ErrUnavailable)
	}
	return nil
}

func (s systemdEncryption) Encrypt(ctx context.Context, plain []byte) ([]byte, error) {
	if err := s.Check(ctx); err != nil {
		return nil, err
	}
	return s.run(ctx, []string{"--user", "--no-ask-password", "--with-key=host", "--name=" + systemdCredentialName, "encrypt", "-", "-"}, plain)
}

func (s systemdEncryption) Decrypt(ctx context.Context, encrypted []byte) ([]byte, error) {
	if err := s.Check(ctx); err != nil {
		return nil, err
	}
	return s.run(ctx, []string{"--user", "--no-ask-password", "--name=" + systemdCredentialName, "decrypt", "-", "-"}, encrypted)
}

type boundedBuffer struct{ data bytes.Buffer }

func (b *boundedBuffer) Bytes() []byte { return b.data.Bytes() }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > maxFileSize-b.data.Len() {
		return 0, errors.New("helper output exceeds size limit")
	}
	return b.data.Write(p)
}

func runSystemd(ctx context.Context, args []string, input []byte) ([]byte, error) {
	var helper string
	// Do not execute a same-named program from the working directory or PATH.
	for _, candidate := range []string{"/usr/bin/systemd-creds", "/bin/systemd-creds"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			helper = candidate
			break
		}
	}
	if helper == "" {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, args...)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(input)
	var output boundedBuffer
	cmd.Stdout = &output
	// Helper diagnostics can echo input: never copy them into errors or logs.
	cmd.Stderr = io.Discard
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "CONTROL_PLANE_") && !strings.HasPrefix(key, "HOST_MONITOR_") && !strings.HasPrefix(key, "OPENAI_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	if err := cmd.Run(); err != nil {
		clear(output.Bytes())
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: systemd-creds operation failed; per-user credential service and noninteractive authorization must be available", ErrUnavailable)
	}
	return output.Bytes(), nil
}
