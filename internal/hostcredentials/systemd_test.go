// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestSystemdVersionAndHeadlessHelperProtocol(t *testing.T) {
	for _, version := range []string{"systemd 255 (255.1)", "unrecognized", "systemd 256 (256.1)", "systemd 262 (262.1)"} {
		codec := systemdEncryption{run: func(context.Context, []string, []byte) ([]byte, error) { return []byte(version), nil }}
		err := codec.Check(context.Background())
		want := version == "systemd 256 (256.1)" || version == "systemd 262 (262.1)"
		if (err == nil) != want {
			t.Fatalf("version %q: %v", version, err)
		}
	}
	secret := []byte("test-secret-stdin-only")
	var calls [][]string
	codec := systemdEncryption{run: func(_ context.Context, args []string, input []byte) ([]byte, error) {
		if reflect.DeepEqual(args, []string{"--version"}) {
			return []byte("systemd 256 (256.1)"), nil
		}
		calls = append(calls, args)
		for _, arg := range args {
			if bytes.Contains([]byte(arg), secret) {
				t.Fatal("secret included in helper arguments")
			}
		}
		if !bytes.Equal(input, secret) {
			t.Fatal("input not passed through stdin")
		}
		return append([]byte(nil), input...), nil
	}}
	for _, op := range []func(context.Context, []byte) ([]byte, error){codec.Encrypt, codec.Decrypt} {
		if _, err := op(context.Background(), secret); err != nil {
			t.Fatal(err)
		}
	}
	want := [][]string{
		{"--user", "--no-ask-password", "--with-key=host", "--name=host-monitor.credentials", "encrypt", "-", "-"},
		{"--user", "--no-ask-password", "--name=host-monitor.credentials", "decrypt", "-", "-"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("helper protocol: %v", calls)
	}
}

func TestSystemdUnavailableAndBoundedOutput(t *testing.T) {
	codec := systemdEncryption{run: func(context.Context, []string, []byte) ([]byte, error) {
		return nil, errors.New("synthetic helper failure")
	}}
	if err := codec.Check(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	var out boundedBuffer
	if _, err := out.Write(make([]byte, maxFileSize+1)); err == nil {
		t.Fatal("unbounded helper output accepted")
	}
	// Exercise the io.Copy path used by os/exec, including ReaderFrom detection.
	if _, err := io.Copy(&out, io.LimitReader(bytes.NewReader(make([]byte, maxFileSize+1)), maxFileSize+1)); err == nil {
		t.Fatal("helper output limit bypassed through io.Copy")
	}
}
