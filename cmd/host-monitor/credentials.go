// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openai/tunnel-client/internal/hostcredentials"
	"golang.org/x/term"
)

type credentialStore interface {
	Path() string
	Backend() string
	Check(context.Context) error
	Exists() (bool, error)
	Load(context.Context) (hostcredentials.Record, error)
	Create(context.Context, hostcredentials.Record) error
	Update(context.Context, func(*hostcredentials.Record) error) error
	Delete(context.Context) error
}

type credentialCLI struct {
	in     io.Reader
	out    io.Writer
	getenv func(string) string
	open   func(string) credentialStore
}

const credentialsHelp = `Manage encrypted local tunnel credentials (no GUI required).

  host-monitor credentials set       Create; refuse to overwrite
  host-monitor credentials update    Change selected fields; require an existing record
  host-monitor credentials delete    Delete local credentials (idempotent)
  host-monitor credentials status    Show metadata and sources, never the API key
  host-monitor credentials doctor    Check the backend and existing file without writing

Options:
  --credentials-file PATH    Override the encrypted credentials file
  --tunnel-id ID            Set/update the tunnel ID
  --api-key-stdin           Read the API key from stdin (never from an argument)
  --base-url URL            Set/update the control-plane URL
  --organization-id ID      Set/update the organization
  --from-env               Explicitly read CONTROL_PLANE_* for set/update
  --unset FIELD            Clear base-url or organization-id (update only; repeatable)
  --json                   Machine-readable status/doctor output

Without input options, set/update prompt in a terminal; API keys are not echoed.
Without a terminal, specify --api-key-stdin or --from-env as appropriate.
Changes affect the next process start. Delete does not revoke a remote API key.
`

type repeatedStrings []string

func (v *repeatedStrings) String() string     { return strings.Join(*v, ",") }
func (v *repeatedStrings) Set(s string) error { *v = append(*v, s); return nil }

func (c credentialCLI) execute(ctx context.Context, args []string, defaultOverride string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprint(c.out, credentialsHelp)
		return err
	}
	action := args[0]
	if action != "set" && action != "update" && action != "delete" && action != "status" && action != "doctor" {
		return usageError("unknown credentials subcommand; use credentials --help")
	}
	flags := flag.NewFlagSet("credentials "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	pathFlag := flags.String("credentials-file", defaultOverride, "")
	tunnelID := flags.String("tunnel-id", "", "")
	baseURL := flags.String("base-url", "", "")
	organization := flags.String("organization-id", "", "")
	keyStdin := flags.Bool("api-key-stdin", false, "")
	fromEnv := flags.Bool("from-env", false, "")
	jsonOutput := flags.Bool("json", false, "")
	var unset repeatedStrings
	flags.Var(&unset, "unset", "")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = fmt.Fprint(c.out, credentialsHelp)
			return err
		}
		return usageError("invalid credentials arguments; use credentials --help")
	}
	if flags.NArg() != 0 {
		return usageError("unexpected positional arguments; use credentials --help")
	}
	visited := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if visited["credentials-file"] && *pathFlag == "" {
		return usageError("--credentials-file cannot be empty")
	}
	inputOptions := visited["tunnel-id"] || visited["base-url"] || visited["organization-id"] || visited["api-key-stdin"] || visited["from-env"] || visited["unset"]
	write := action == "set" || action == "update"
	if (!write && inputOptions) || (write && visited["json"]) || (action == "delete" && visited["json"]) {
		return usageError("options do not apply to this credentials subcommand")
	}
	if *fromEnv && (visited["tunnel-id"] || visited["base-url"] || visited["organization-id"] || visited["api-key-stdin"] || visited["unset"]) {
		return usageError("--from-env cannot be combined with other credential input options")
	}
	if len(unset) > 0 && action != "update" {
		return usageError("--unset is only supported by credentials update")
	}
	for _, field := range unset {
		if (field != "base-url" && field != "organization-id") || visited[field] {
			return usageError("--unset accepts base-url or organization-id and cannot be combined with setting that field")
		}
	}
	path, err := hostcredentials.ResolvePath(*pathFlag, c.getenv)
	if err != nil {
		return err
	}
	store := c.open(path)
	if action == "status" || action == "doctor" {
		return c.status(ctx, store, action == "doctor", *jsonOutput)
	}
	if action == "delete" {
		if err := store.Delete(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintf(c.out, "Local credentials deleted (if present): %s\nRestart running processes to stop using credentials already loaded in memory.\n", store.Path())
		return err
	}
	exists, err := store.Exists()
	if err != nil {
		return err
	}
	if action == "set" && exists {
		return hostcredentials.ErrExists
	}
	if action == "update" && !exists {
		return hostcredentials.ErrNotFound
	}
	patch := make(map[string]string)
	if *fromEnv {
		for field, env := range credentialEnvNames {
			if value := strings.TrimSpace(c.getenv(env)); value != "" {
				patch[field] = value
			}
		}
	} else {
		for field, value := range map[string]string{"tunnel-id": *tunnelID, "base-url": *baseURL, "organization-id": *organization} {
			if visited[field] {
				patch[field] = strings.TrimSpace(value)
			}
		}
		if *keyStdin {
			input, err := io.ReadAll(io.LimitReader(c.in, (16<<10)+1))
			if err != nil || len(input) > 16<<10 {
				clear(input)
				return errors.New("cannot read API key from stdin or input exceeds 16 KiB")
			}
			patch["api-key"] = strings.TrimSpace(string(input))
			clear(input)
		}
		if !inputOptions || (action == "set" && !*keyStdin && (patch["tunnel-id"] == "" || patch["api-key"] == "")) {
			if err := c.prompt(action == "update", patch); err != nil {
				return err
			}
		}
	}
	for _, field := range unset {
		patch[field] = ""
	}
	if action == "update" && len(patch) == 0 {
		return usageError("no credential changes supplied")
	}
	apply := func(record *hostcredentials.Record) error {
		for field, value := range patch {
			switch field {
			case "tunnel-id":
				record.TunnelID = value
			case "api-key":
				record.APIKey = value
			case "base-url":
				record.BaseURL = value
			case "organization-id":
				record.OrganizationID = value
			}
		}
		return nil
	}
	if action == "set" {
		var record hostcredentials.Record
		_ = apply(&record)
		err = store.Create(ctx, record)
	} else {
		err = store.Update(ctx, apply)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.out, "Encrypted credentials saved: %s\nChanges take effect on the next process start.\n", store.Path())
	return err
}

var credentialEnvNames = map[string]string{
	"tunnel-id": "CONTROL_PLANE_TUNNEL_ID", "api-key": "CONTROL_PLANE_API_KEY",
	"base-url": "CONTROL_PLANE_BASE_URL", "organization-id": "CONTROL_PLANE_ORGANIZATION_ID",
}

func (c credentialCLI) prompt(update bool, patch map[string]string) error {
	file, ok := c.in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return usageError("no terminal available; use --from-env or --tunnel-id with --api-key-stdin")
	}
	for _, field := range []string{"tunnel-id", "api-key", "base-url", "organization-id"} {
		if _, supplied := patch[field]; supplied {
			continue
		}
		suffix := ""
		if update {
			suffix = " (blank keeps current value)"
		}
		fmt.Fprintf(c.out, "%s%s: ", field, suffix)
		var value string
		if field == "api-key" {
			secret, err := term.ReadPassword(int(file.Fd()))
			fmt.Fprintln(c.out)
			if err != nil || len(secret) > 16<<10 {
				clear(secret)
				return errors.New("could not read hidden API key from terminal")
			}
			value = strings.TrimSpace(string(secret))
			clear(secret)
		} else {
			// Avoid prefetching the secret line before ReadPassword disables echo.
			var line strings.Builder
			one := make([]byte, 1)
			for {
				n, err := c.in.Read(one)
				if n == 1 && one[0] == '\n' {
					break
				}
				if err != nil || line.Len() >= 16<<10 {
					return errors.New("could not read credential field from terminal")
				}
				if n == 1 {
					line.WriteByte(one[0])
				}
			}
			value = strings.TrimSpace(line.String())
		}
		if value != "" || !update {
			patch[field] = value
		}
	}
	return nil
}

type credentialStatus struct {
	Path             string            `json:"path"`
	Backend          string            `json:"backend"`
	Exists           bool              `json:"exists"`
	Readable         bool              `json:"readable"`
	BackendAvailable *bool             `json:"backend_available,omitempty"`
	TunnelID         string            `json:"tunnel_id,omitempty"`
	APIKeyConfigured bool              `json:"api_key_configured"`
	CreatedAt        string            `json:"created_at,omitempty"`
	UpdatedAt        string            `json:"updated_at,omitempty"`
	Sources          map[string]string `json:"sources"`
	Detail           string            `json:"detail,omitempty"`
}

func (c credentialCLI) status(ctx context.Context, store credentialStore, doctor, jsonOutput bool) error {
	out := credentialStatus{Path: store.Path(), Backend: store.Backend(), Sources: make(map[string]string)}
	var operationErr error
	if doctor {
		err := store.Check(ctx)
		available := err == nil
		out.BackendAvailable = &available
		operationErr = err
		out.Detail = "Backend detection does not prove encryption authorization. No files are created or changed."
	}
	exists, err := store.Exists()
	if err != nil {
		operationErr = err
	}
	out.Exists = exists
	var record hostcredentials.Record
	if exists && err == nil {
		record, err = store.Load(ctx)
		if err != nil {
			operationErr = err
		} else {
			out.Readable, out.APIKeyConfigured = true, true
			out.TunnelID, out.CreatedAt, out.UpdatedAt = record.TunnelID, record.CreatedAt, record.UpdatedAt
		}
	}
	fullEnv := strings.TrimSpace(c.getenv("CONTROL_PLANE_TUNNEL_ID")) != "" && strings.TrimSpace(c.getenv("CONTROL_PLANE_API_KEY")) != ""
	for field, env := range credentialEnvNames {
		source := "unset"
		if strings.TrimSpace(c.getenv(env)) != "" {
			source = "environment"
		} else if out.Readable && !fullEnv {
			switch field {
			case "tunnel-id", "api-key":
				source = "encrypted-file"
			case "base-url":
				if record.BaseURL != "" {
					source = "encrypted-file"
				}
			case "organization-id":
				if record.OrganizationID != "" {
					source = "encrypted-file"
				}
			}
		}
		if field == "base-url" && source == "unset" {
			source = "SDK-default"
		}
		out.Sources[field] = source
	}
	if operationErr != nil {
		out.Detail = operationErr.Error()
	}
	if jsonOutput {
		if err := json.NewEncoder(c.out).Encode(out); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(c.out, "Path: %s\nBackend: %s\nStored: %t\nReadable: %t\nAPI key stored: %t (value never displayed)\n", out.Path, out.Backend, out.Exists, out.Readable, out.APIKeyConfigured)
		if out.BackendAvailable != nil {
			fmt.Fprintf(c.out, "Backend detected: %t\n", *out.BackendAvailable)
		}
		for _, field := range []string{"tunnel-id", "api-key", "base-url", "organization-id"} {
			fmt.Fprintf(c.out, "%s source: %s\n", field, out.Sources[field])
		}
		if out.Detail != "" {
			fmt.Fprintln(c.out, out.Detail)
		}
	}
	return operationErr
}

type commandError struct{ message string }

func (e commandError) Error() string  { return e.message }
func usageError(message string) error { return commandError{message} }
