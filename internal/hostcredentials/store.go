// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

// Package hostcredentials stores local tunnel credentials with OS encryption.
// It is used by the local CLI, never exposed as an MCP tool.
package hostcredentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxPlaintext = 16 << 10
	maxFileSize  = 128 << 10
	fileHeader   = "HOST-MONITOR-CREDENTIALS-V1\n"
)

var (
	ErrExists      = errors.New("credentials already exist; use credentials update")
	ErrNotFound    = errors.New("credentials file not found")
	ErrUnavailable = errors.New("OS credential encryption is unavailable")
)

// Record is always encrypted as a whole, including its metadata.
type Record struct {
	Version        int    `json:"version"`
	TunnelID       string `json:"tunnel_id"`
	APIKey         string `json:"api_key"`
	BaseURL        string `json:"base_url,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

func (Record) String() string     { return "[encrypted credential record; values redacted]" }
func (r Record) GoString() string { return r.String() }

func (r Record) Validate() error {
	if r.TunnelID == "" || r.APIKey == "" {
		return errors.New("tunnel ID and API key must both be nonempty")
	}
	for _, value := range []string{r.TunnelID, r.APIKey, r.BaseURL, r.OrganizationID} {
		if !utf8.ValidString(value) || value != strings.TrimSpace(value) || strings.ContainsFunc(value, unicode.IsControl) {
			return errors.New("credential fields must not contain control characters or surrounding whitespace")
		}
	}
	if r.BaseURL != "" {
		u, err := url.Parse(r.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("base URL must be an HTTP(S) URL without user information, query or fragment")
		}
	}
	return nil
}

type encryption interface {
	Name() string
	Check(context.Context) error
	Encrypt(context.Context, []byte) ([]byte, error)
	Decrypt(context.Context, []byte) ([]byte, error)
}

type Store struct {
	path   string
	crypto encryption
}

// ResolvePath does not create files or directories. Overrides select exactly
// one file; no other store is searched or moved.
func ResolvePath(override string, getenv func(string) string) (string, error) {
	if override == "" {
		override = getenv("HOST_MONITOR_CREDENTIALS_FILE")
	}
	if override == "" {
		var err error
		override, err = defaultPath(getenv)
		if err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(override) == "" || strings.ContainsRune(override, 0) {
		return "", errors.New("credentials path must be nonempty and contain no NUL")
	}
	path, err := filepath.Abs(override)
	if err != nil {
		return "", errors.New("could not resolve the credentials path")
	}
	return filepath.Clean(path), nil
}

func New(path string) *Store                     { return &Store{path: path, crypto: platformEncryption()} }
func (s *Store) Path() string                    { return s.path }
func (s *Store) Backend() string                 { return s.crypto.Name() }
func (s *Store) Check(ctx context.Context) error { return s.crypto.Check(ctx) }

// Exists inspects only the directory entry; no decryption or directory creation.
func (s *Store) Exists() (bool, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("cannot inspect credentials file")
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("credentials path must be a regular file, not a link or directory")
	}
	return true, nil
}

func (s *Store) Load(ctx context.Context) (Record, error) {
	f, err := openPrivateRead(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("cannot read protected credentials file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil || len(data) > maxFileSize {
		return Record{}, errors.New("credentials file is unreadable or exceeds size limit")
	}
	prefix := fileHeader + s.crypto.Name() + "\n"
	if !strings.HasPrefix(string(data), prefix) {
		return Record{}, errors.New("unrecognized credential format or encryption backend")
	}
	plain, err := s.crypto.Decrypt(ctx, data[len(prefix):])
	if err != nil {
		return Record{}, err
	}
	defer clear(plain)
	if len(plain) > maxPlaintext {
		return Record{}, errors.New("decrypted credential exceeds size limit")
	}
	var record Record
	if json.Unmarshal(plain, &record) != nil || record.Version != 1 {
		return Record{}, errors.New("invalid or unsupported encrypted credential record")
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Store) Create(ctx context.Context, record Record) error {
	return s.change(ctx, true, func(current *Record) error { *current = record; return nil })
}

func (s *Store) Update(ctx context.Context, patch func(*Record) error) error {
	return s.change(ctx, false, patch)
}

func (s *Store) change(ctx context.Context, create bool, patch func(*Record) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := makePrivateDirs(dir); err != nil {
		return fmt.Errorf("cannot prepare credentials directory: %w", err)
	}
	unlock, err := lockStore(ctx, s.path)
	if err != nil {
		return err
	}
	defer unlock()
	exists, err := s.Exists()
	if err != nil {
		return err
	}
	if create && exists {
		return ErrExists
	}
	if !create && !exists {
		return ErrNotFound
	}
	var record Record
	if !create {
		record, err = s.Load(ctx)
		if err != nil {
			return err
		}
	}
	if err := patch(&record); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record.Version = 1
	if create {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	plain, err := json.Marshal(record)
	defer clear(plain)
	if err != nil || len(plain) > maxPlaintext {
		return errors.New("credential record exceeds size limit")
	}
	ciphertext, err := s.crypto.Encrypt(ctx, plain)
	if err != nil {
		return err
	}
	data := append([]byte(fileHeader+s.crypto.Name()+"\n"), ciphertext...)
	if len(data) > maxFileSize {
		return errors.New("encrypted credential exceeds size limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeAtomic(s.path, data, create)
}

func (s *Store) Delete(ctx context.Context) error {
	exists, err := s.Exists()
	if err != nil || !exists {
		return err
	}
	unlock, err := lockStore(ctx, s.path)
	if err != nil {
		return err
	}
	defer unlock()
	exists, err = s.Exists()
	if err != nil || !exists {
		return err
	}
	if err := os.Remove(s.path); err != nil {
		return errors.New("cannot delete credentials file")
	}
	return nil
}

func writeAtomic(path string, data []byte, create bool) error {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return errors.New("cannot generate temporary filename")
	}
	tmp := filepath.Join(filepath.Dir(path), ".host-monitor-"+hex.EncodeToString(random)+".tmp")
	f, err := createPrivateFile(tmp)
	if err != nil {
		return errors.New("cannot create protected temporary credentials file")
	}
	defer os.Remove(tmp)
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("cannot write encrypted credentials; previous credentials retained")
	}
	if err := publishFile(tmp, path, create); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return errors.New("cannot replace encrypted credentials; previous credentials retained")
	}
	return nil
}
