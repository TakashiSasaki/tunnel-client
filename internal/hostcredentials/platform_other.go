// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

//go:build !windows && !linux

package hostcredentials

import (
	"context"
	"os"
)

type unsupportedEncryption struct{}

func (unsupportedEncryption) Name() string                { return "unsupported" }
func (unsupportedEncryption) Check(context.Context) error { return ErrUnavailable }
func (unsupportedEncryption) Encrypt(context.Context, []byte) ([]byte, error) {
	return nil, ErrUnavailable
}
func (unsupportedEncryption) Decrypt(context.Context, []byte) ([]byte, error) {
	return nil, ErrUnavailable
}
func platformEncryption() encryption                    { return unsupportedEncryption{} }
func defaultPath(func(string) string) (string, error)   { return "", ErrUnavailable }
func makePrivateDirs(string) error                      { return ErrUnavailable }
func openPrivateRead(string) (*os.File, error)          { return nil, ErrUnavailable }
func createPrivateFile(string) (*os.File, error)        { return nil, ErrUnavailable }
func publishFile(string, string, bool) error            { return ErrUnavailable }
func lockStore(context.Context, string) (func(), error) { return nil, ErrUnavailable }
