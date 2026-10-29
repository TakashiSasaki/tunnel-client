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
	maxPlaintext    = 16 << 10
	maxFileSize     = 128 << 10
	fileHeader      = "HOST-MONITOR-CREDENTIALS-V1\n"
	adminFileHeader = "HOST-MONITOR-ADMIN-CREDENTIALS-V1\n"
)

var (
	ErrExists      = errors.New("credentials already exist; use credentials update")
	ErrNotFound    = errors.New("credentials file not found")
	ErrUnavailable = errors.New("OS credential encryption is unavailable")
	ErrKind        = errors.New("credential type does not match the selected store")
)

type Kind string

const (
	Runtime Kind = "runtime"
	Admin   Kind = "admin"
)

func (k Kind) Valid() bool { return k == Runtime || k == Admin }

// Record is always encrypted as a whole, including its metadata.
type Record struct {
	Version        int    `json:"version"`
	Kind           Kind   `json:"type,omitempty"`
	TunnelID       string `json:"tunnel_id"`
	APIKey         string `json:"api_key"`
	BaseURL        string `json:"base_url,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

func (Record) String() string     { return "[encrypted credential record; values redacted]" }
func (r Record) GoString() string { return r.String() }

// Records written before type selection was introduced are runtime credentials.
func (r Record) EffectiveKind() Kind {
	if r.Kind == "" {
		return Runtime
	}
	return r.Kind
}

func (r Record) Validate() error {
	if !r.EffectiveKind().Valid() {
		return errors.New("credential type must be runtime or admin")
	}
	if r.APIKey == "" {
		return errors.New("API key must be nonempty")
	}
	if r.EffectiveKind() == Runtime && r.TunnelID == "" {
		return errors.New("tunnel ID must be nonempty for runtime credentials")
	}
	if r.EffectiveKind() == Admin && r.TunnelID != "" {
		return errors.New("admin credentials are not tied to a tunnel ID")
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
	kind   Kind
}

// ResolvePath does not create files or directories. Overrides select exactly
// one file; no other store is searched or moved.
func ResolvePath(override string, getenv func(string) string) (string, error) {
	return ResolvePathFor(Runtime, override, getenv)
}

// Admin has its own override and default file; --credentials-file remains the
// exact selected filename for either kind, without suffix rewriting.
func ResolvePathFor(kind Kind, override string, getenv func(string) string) (string, error) {
	if !kind.Valid() {
		return "", errors.New("credential type must be runtime or admin")
	}
	if override == "" {
		env := "HOST_MONITOR_CREDENTIALS_FILE"
		if kind == Admin {
			env = "HOST_MONITOR_ADMIN_CREDENTIALS_FILE"
		}
		override = getenv(env)
	}
	if override == "" {
		var err error
		override, err = defaultPath(getenv)
		if err != nil {
			return "", err
		}
		if kind == Admin {
			override = filepath.Join(filepath.Dir(override), "credentials.admin.enc")
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

func New(path string) *Store { return NewForKind(path, Runtime) }
func NewForKind(path string, kind Kind) *Store {
	return &Store{path: path, crypto: platformEncryption(), kind: kind}
}
func (s *Store) Kind() Kind {
	if s.kind == "" {
		return Runtime
	}
	return s.kind
}
func (s *Store) prefix() string {
	header := fileHeader
	if s.Kind() == Admin {
		header = adminFileHeader
	}
	return header + s.crypto.Name() + "\n"
}
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
	if !s.Kind().Valid() {
		return Record{}, ErrKind
	}
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
	prefix := s.prefix()
	if !strings.HasPrefix(string(data), prefix) {
		otherHeader := adminFileHeader
		if s.Kind() == Admin {
			otherHeader = fileHeader
		}
		if strings.HasPrefix(string(data), otherHeader) {
			return Record{}, ErrKind
		}
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
	if record.EffectiveKind() != s.Kind() {
		return Record{}, ErrKind
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
	if !s.Kind().Valid() {
		return ErrKind
	}
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
	if record.EffectiveKind() != s.Kind() {
		return ErrKind
	}
	if err := record.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record.Version = 1
	record.Kind = s.Kind()
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
	data := append([]byte(s.prefix()), ciphertext...)
	if len(data) > maxFileSize {
		return errors.New("encrypted credential exceeds size limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeAtomic(s.path, data, create)
}

func (s *Store) Delete(ctx context.Context) error {
	if !s.Kind().Valid() {
		return ErrKind
	}
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
	// The public type header lets deletion reject the wrong kind without
	// decrypting either key or needing the Linux encryption service.
	f, err := openPrivateRead(s.path)
	if err != nil {
		return errors.New("cannot inspect credentials before deletion")
	}
	header, readErr := io.ReadAll(io.LimitReader(f, int64(len(s.prefix()))))
	_ = f.Close()
	if readErr != nil || string(header) != s.prefix() {
		return ErrKind
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
