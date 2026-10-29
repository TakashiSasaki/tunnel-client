# Read-only host monitor

Original host-monitor additions by TAKASHI SASAKI ([takashi316@gmail.com](mailto:takashi316@gmail.com)) are licensed under the
[MIT License](../LICENSE-MIT). The OpenAI tunnel client used by this command
retains its [Apache License 2.0](../LICENSE) and [NOTICE](../NOTICE), and
third-party dependencies retain their respective licenses.

`host-monitor` combines a host-monitoring MCP server and the OpenAI Secure MCP
Tunnel client and local credential-management CLI in one Go executable.
Environment variables override an optional OS-encrypted credential file.
Monitoring opens no local HTTP listener or admin UI and creates no configuration,
log, or history files. Only explicit local credential commands create, update
or delete the encrypted credential file. Log messages go to stderr.

Windows and Linux are the initial supported targets. The common monitoring tools
and JSON field names are used on both; Windows additionally exposes `screenshot`.
OS data comes from the machine running the binary.
It is collected on demand, with no background sampling or metrics history.

## Tools

| Tool | Information | Arguments |
| --- | --- | --- |
| `host_info` | Hostname, OS, architecture, uptime and logical CPU count | None |
| `cpu_usage` | Total and per-logical-CPU utilization over a sampling interval | `sample_ms`: default 200, allowed 100–2000 |
| `memory_usage` | Physical RAM total, available, used and percentage | None |
| `swap_usage` | Linux swap / Windows pagefile capacity and usage, per device | None |
| `disk_usage` | Local filesystem capacity and usage | None |
| `disk_io` | Cumulative disk read/write bytes and operation counts | None |
| `network_io` | Cumulative per-interface bytes, packets, errors and drops | None |
| `process_list` | PID, name, parent PID, username, resident RAM, CPU seconds, threads and creation time where accessible | `offset`: default 0; `limit`: default 100, maximum 500; optional positive `pid` |
| `logged_in_users` | Logged-in sessions | None |
| `cpu_info` | CPU models, vendors, physical/logical configuration and reported clocks where available | None |
| `gpu_info` | OS-reported graphics/video controllers and existing driver details | None |
| `device_list` | Existing OS device inventory | `bus`: `all` (default), `pci`, `usb`; `offset`: default 0; `limit`: default 100, maximum 500 |
| `temperatures` | Available sensor readings in Celsius, with names, kinds and sources | None |
| `host_snapshot` | Selected monitoring results in one call, retaining successful items if others fail | Required `include` list of monitoring tool names; optional `cpu`, `process`, `devices` options |
| `screenshot` (Windows only) | Current visible desktop as a PNG MCP image, plus image metadata | `display`: `primary` (default) or `all`; `max_width`: default 1280; `max_height`: default 720 |

Each result contains `snapshot.observed_at` (UTC RFC3339) and `snapshot.os`.
Byte measurements are bytes. CPU and memory percentages are 0–100. Per-process
CPU time is cumulative seconds, not percent. Disk and network counters are
cumulative, not rates; compare two snapshots of the same device to derive a rate
and allow for resets/reboots. Windows disk counters come from the existing
`Win32_PerfRawData_PerfDisk_PhysicalDisk` WMI provider: its `PerSec` property
names contain raw cumulative numerators, not already calculated rates.

Process pages are fresh snapshots sorted by PID; processes can start or exit
between pages. `pid` selects one process instead of a page and cannot be combined
with a nonzero `offset`. A process that exits or cannot be inspected retains its
PID and reports missing fields in `unavailable_fields`. Command lines and
environment variables are not collected. Missing measurements are not reported
as zeroes.

`logged_in_users` lists sessions, not all configured accounts. Windows includes
active and disconnected sessions and reports their state. Linux reads the OS
login-session database; containers and systems without that database return an
empty list with an explicit warning. Inaccessible volumes/sessions also produce
warnings rather than concealing the incomplete result.

The agent does not execute caller-provided commands, read arbitrary file
contents, write files, change registry settings, enable performance counters,
adjust privileges, install services, or control processes. Windows adapters
avoid `gopsutil/host`, `gopsutil/process` and `gopsutil/disk`, whose initialization
would otherwise adjust debug privileges or disk counter settings. Unavailable
disk counters are reported as an error and are not enabled by the agent.

Reading metrics still consumes a small amount of CPU and OS query work. Tool
contexts default to 10 seconds. Native OS calls do not all support immediate
cancellation: a timeout is not a promise to forcibly interrupt an OS call.
Windows WMI disk queries are serialized and keep their slot until the query
finishes, even after a caller timeout, to bound unfinished background work.

Event logs, journal queries, alerting and historical storage are outside this
initial implementation. These can be added separately without changing the
single-binary deployment model.

## Aggregate monitoring

Call `host_snapshot` to select up to 13 monitoring items in a single MCP tool
request. `include` is required, nonempty, and uses the exact individual tool
names listed above. Unknown or duplicate names reject the request before any
collection starts. Screenshots and nested `host_snapshot` calls are excluded.

Example tool arguments:

```json
{
  "include": ["host_info", "cpu_usage", "memory_usage", "swap_usage", "disk_usage", "process_list", "temperatures"],
  "cpu": {"sample_ms": 200},
  "process": {"limit": 20}
}
```

`cpu`, `process`, and `devices` pass options to `cpu_usage`, `process_list`, and
`device_list`, respectively. They use the individual tools' defaults and bounds
and are ignored when their item is not selected. For example, to include the
first five USB devices, add `device_list` to `include` and pass
`"devices": {"bus": "usb", "limit": 5}`. Process/device lists remain paginated;
the aggregate does not automatically fetch additional pages.

The structured response contains:

- `include`: the requested names, in input order.
- `results`: successful results keyed by tool name, with the same fields as
  individual calls (including their own timestamps, warnings and source status).
- `errors`: failed or unfinished items keyed by tool name, with an error message.
- `complete`: true only when every requested collector succeeds. It does not
  guarantee every field, device or temperature source is available; consult each
  item's warnings, unavailable fields and source statuses.
- `snapshot.observed_at` and `finished_at`: collection start and finish times.

At most four collectors run concurrently, within one shared
`HOST_MONITOR_TIMEOUT` budget for the whole request. A collector failure,
invalid item-specific option, or timeout retains successful results and reports
the affected items in `errors`, rather than turning the whole response into an
MCP tool error. Invalid `include` selections are MCP errors. Explicit client
cancellation may prevent delivery of any response. An OS query that cannot be
interrupted may finish after timeout; its late result is discarded.

Measurements are collected over an interval, not atomically at one instant.
Use each item's timestamp when comparing counters. The aggregate adds no
background monitoring, configuration files, or host modifications.

## Hardware inventory and available temperatures

Hardware information is obtained from the environment as it exists. The agent
does not install software or drivers, load kernel modules, start monitoring
programs, request device rescans, enable sensors or change power/fan settings.
It performs OS queries only when a tool is called.

- Windows CPU information uses `Win32_Processor`. GPU information uses
  `Win32_VideoController`; it can include virtual/software video adapters, so a
  controller entry is not proof of a physical discrete GPU. VRAM sizes are not
  guessed from the class's limited-width `AdapterRAM` property.
- Windows device inventory uses a fixed `Win32_PnPEntity` SELECT for currently
  present devices. No PnP methods or command-line programs are invoked.
- Linux CPU information uses existing `/proc/cpuinfo` data and preserves missing
  physical topology as unknown. It distinguishes physical cores from logical
  threads within a socket. Reported clock values are OS readings, not a promise
  about instantaneous frequency or a hardware maximum.
- Linux device inventory reads informational PCI/USB sysfs attributes and the
  existing driver symlink. It does not read PCI config space, ROMs or raw device
  resources. Names may fall back to vendor/device IDs when the OS does not
  expose a friendly name; there is no downloaded PCI-ID database. GPU inventory
  selects PCI graphics-class devices, and may read an already-loaded NVIDIA
  driver's existing proc information for its model name. No NVIDIA commands or
  vendor libraries are initialized by this implementation.

Inventory and temperature results include `sources` with a source name, status,
record count and an optional failure detail. `available` with zero records means
the query succeeded without finding records; `unavailable` means the source could
not be queried. Source counts refer to records observed at that source, before
device bus filtering. An empty GPU list with an unavailable source must not be
interpreted as proof that no GPU is installed. Device pages are sorted by bus/ID
and are fresh snapshots; hotplug can change subsequent pages. Enumeration is
bounded at 4096 device records, reported by `truncated` when reached.

Temperature sources in this version are:

- Linux: existing `hwmon/temp*_input` and `thermal_zone*/temp` attributes. Values
  are interpreted using the kernel's millidegree Celsius interface. Driver and
  sensor labels are retained; unknown thermal zones are not renamed CPU cores.
  Disabled or faulted sensors are skipped without attempting to enable/reset
  them. Hwmon and thermal interfaces may expose the same physical sensor.
- Windows: available ACPI thermal-zone readings and temperature sensors already
  published in the `root/LibreHardwareMonitor` or `root/OpenHardwareMonitor` WMI
  namespaces. The namespace is checked before querying. Neither monitoring
  program is installed or started. Each WMI temperature probe has a 2-second
  budget within the tool timeout, so a failing provider can be reported while
  retaining other readings.

`temperatures.sensors` contains only valid numeric readings, including genuine
0°C values. Missing, disabled, invalid or inaccessible readings are omitted with
source status and/or bounded warnings; they are never converted into 0°C. Each
reading includes its sensor name, kind and exact source. The snapshot timestamp
is the collection time, not proof of when a third-party provider refreshed its
sensor value. At most 512 readings are returned, with `truncated` when bounded.

Temperature availability depends on existing drivers, firmware and permissions.
This implementation does not promise CPU core/GPU temperatures on every machine
and does not try to make an unavailable sensor readable. No additional runtime
or configuration file is required. Standard Linux `HOST_SYS` and `HOST_PROC`
environment overrides are honored when the OS views are mounted elsewhere.

Implementation references:
[CPU WMI](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor),
[PnP WMI](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-pnpentity),
[PCI sysfs](https://docs.kernel.org/PCI/sysfs-pci.html),
[hwmon units and labels](https://docs.kernel.org/hwmon/sysfs-interface.html).

## Windows screenshots

`screenshot` returns one `image/png` MCP image and structured metadata including
the original desktop bounds, output dimensions and PNG byte count. The PNG is
created in memory and sent in the tool response; it is never saved to a file or
written to logs. No extra runtime, executable, configuration or environment
variable is required.

Example MCP tool arguments:

```json
{"display":"primary","max_width":1280,"max_height":720}
```

Set `display` to `all` to capture the virtual desktop spanning all monitors,
including monitors with negative desktop coordinates. `primary` captures only
the main screen. Images preserve aspect ratio and are never enlarged. Width and
height bounds must each be between 1 and 4096; output is limited to 4,194,304
pixels and a 6 MiB encoded PNG. Lower the bounds if the PNG exceeds that limit.
The base64 image and metadata fit within the default tunnel response limit.
Captures are serialized to bound memory use; waiting captures honor the tool
timeout.

Capture reads the current user session's existing desktop using Windows GDI. It
does not move the cursor, send input, change focus, switch desktops, or alter
display settings. Per-thread DPI awareness is temporarily adjusted and restored
on the same OS thread so desktop coordinates use physical pixels. The cursor is
not included. Protected content and some hardware-accelerated video may appear
blank. The implementation follows Microsoft's
[in-memory capture](https://learn.microsoft.com/en-us/windows/win32/gdi/capturing-an-image)
and [DIB synchronization](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createdibsection)
requirements.

An accessible interactive desktop is required. Session 0 services and inaccessible
or different input desktops return an explicit tool error. Locked/secure desktop
access is not enabled and another user's session is not selected. Linux does
not advertise this tool.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `HOST_MONITOR_TRANSPORT` | `tunnel` | `tunnel` for the built-in client, or `stdio` for a local MCP client |
| `CONTROL_PLANE_TUNNEL_ID` | Saved value, or required in tunnel mode | Existing OpenAI tunnel identity |
| `CONTROL_PLANE_API_KEY` | Saved value, or required in tunnel mode | Runtime key with Tunnels Read + Use |
| `CONTROL_PLANE_BASE_URL` | SDK default: `https://api.openai.com` | Optional control-plane host override |
| `CONTROL_PLANE_ORGANIZATION_ID` | Unset | Optional Platform organization |
| `HOST_MONITOR_TIMEOUT` | `10s` | Per-tool context timeout; allowed `100ms`–`120s` |
| `HOST_MONITOR_CREDENTIALS_FILE` | OS-specific path below | Runtime credential file; overridden by `--credentials-file` |
| `HOST_MONITOR_ADMIN_CREDENTIALS_FILE` | Adjacent `credentials.admin.enc` in the OS default folder | Admin credential file for `credentials --type admin`; never used by monitor startup |
| `OPENAI_ADMIN_KEY` | Unset | Imported only by `credentials set/update --type admin --from-env`; never a runtime fallback |

There is no plaintext configuration-file option. Nonempty credential environment
variables override corresponding saved fields; empty/whitespace values are treated
as unset. When both tunnel ID and API key are supplied via environment, the saved
file is bypassed entirely, including its optional URL/organization fields. Supply
those optional environment variables too if needed. Stdio mode never reads the
credential file. A missing store is allowed if the required environment is present;
an unreadable or corrupt selected store is an error when fallback is needed.
The inherited HTTP proxy environment remains available to the tunnel client's
HTTP transport. Do not embed an API key in the binary. Use a runtime key, not an
organization admin key.

In tunnel mode, the embedded MCP server connects to the tunnel client through
in-memory transports. No separate MCP process or listening port is needed.
OpenAI-side tunnel identity, access and product setup are still required; see
the [official Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

PowerShell, after setting the two required credential environment variables:

```powershell
.\host-monitor.exe
```

For an existing local MCP client, set its child process environment to:

```powershell
$env:HOST_MONITOR_TRANSPORT = 'stdio'
.\host-monitor.exe
```

Stdio mode expects MCP JSON-RPC on stdin/stdout and does not need tunnel
credentials. Running it in an interactive terminal will wait for MCP input.

Linux uses the same environment variables:

```sh
./host-monitor
```

Startup is distinct from remote connectivity. The stderr message
`host-monitor: tunnel polling connected` means the first control-plane poll
succeeded; it does not mean that a tool has been called from ChatGPT/Codex.

## Local encrypted credentials

The same executable provides `credentials set`, `update`, `delete`, `status`,
and `doctor`. Every operation requires explicit `--type runtime` or `--type admin`.
These are local CLI commands, not MCP tools. They do not contact
OpenAI, issue/revoke API keys, or restart an existing monitor. Stored changes apply
on the next start. Run the commands under the same OS account as the monitor.

Runtime credentials contain the runtime API key and tunnel ID. Admin credentials
contain a separate admin API key and do not require or accept a tunnel ID. Both
types can also store a URL and organization ID. The type is a local declaration;
the CLI does not verify the key's permissions with OpenAI. Saving an admin key
does not add remote tunnel-management commands to `host-monitor` or configure
the separate upstream `tunnel-client` CLI.

Existing version-1 runtime files without a `type` field remain readable as runtime
credentials and do not need an explicit migration. Normal monitor startup never
reads the admin file or falls back to `OPENAI_ADMIN_KEY`. The command syntax now
requires type selection, including for read-only status/doctor commands.

| OS | Runtime file | Admin file |
| --- | --- | --- |
| Windows | `%LOCALAPPDATA%\TakashiSasaki\HostMonitor\credentials.enc` | Same default directory, `credentials.admin.enc` |
| Linux | `$XDG_DATA_HOME/host-monitor/credentials.enc` | Same default directory, `credentials.admin.enc` |
| Linux with unset/empty `XDG_DATA_HOME` | `$HOME/.local/share/host-monitor/credentials.enc` | Same default directory, `credentials.admin.enc` |

Windows resolves LocalAppData with the Known Folder API. Relative `XDG_DATA_HOME`
is ignored per the XDG specification. File selection is `--credentials-file PATH`
first, then `HOST_MONITOR_CREDENTIALS_FILE` for runtime or
`HOST_MONITOR_ADMIN_CREDENTIALS_FILE` for admin, then the default above. The two
environment overrides are independent: a custom runtime path does not relocate
the admin file. An explicit path is used exactly as given for the selected type;
no suffix is appended to an override. Relative
overrides resolve against the command's working directory. All operations use
exactly the selected path; choosing another path does not move an existing file.
The path option works on normal startup and after a credential subcommand:

```text
host-monitor --credentials-file /absolute/path/credentials.enc
host-monitor credentials status --type runtime --credentials-file /absolute/path/credentials.enc
```

In Windows PowerShell (add `.exe` to the command on Windows):

```powershell
.\host-monitor.exe credentials set --type runtime
.\host-monitor.exe credentials set --type admin
.\host-monitor.exe credentials status --type runtime --json
.\host-monitor.exe credentials status --type admin --json
.\host-monitor.exe credentials update --type admin
.\host-monitor.exe credentials delete --type admin
.\host-monitor.exe credentials doctor --type runtime --json
```

`set` refuses to overwrite an existing file; `update` requires an existing record
and changes only specified fields. With no input options they prompt in the
terminal. API-key input has echo disabled. During interactive update, a blank
answer retains the current value. To clear optional fields, use
`credentials update --type runtime --unset base-url --unset organization-id`.

For automation, pipe the API key from a secret provider into
`host-monitor credentials set --type runtime --tunnel-id tunnel_... --api-key-stdin` or
`host-monitor credentials update --type runtime --api-key-stdin`.
For admin credentials, use `host-monitor credentials set --type admin --api-key-stdin`
or `host-monitor credentials update --type admin --api-key-stdin`.
No API-key argument exists.
Stdin is a single UTF-8 key (optional trailing newline), bounded at 16 KiB;
embedded control characters are rejected. Without a terminal, a command never
falls back to a GUI or waits for interactive input. To explicitly migrate existing
runtime `CONTROL_PLANE_*` variables, use `credentials set --type runtime --from-env`
or `credentials update --type runtime --from-env`. With `--type admin`,
`--from-env` reads `OPENAI_ADMIN_KEY` and optional `CONTROL_PLANE_BASE_URL` /
`CONTROL_PLANE_ORGANIZATION_ID`, and ignores the runtime key and tunnel ID.
Other management commands never import ambient
credentials. Empty optional fields can also be set with `--base-url=` or
`--organization-id=`. A complete record, including metadata, is limited to 16 KiB.

`status` and `doctor` show the selected type, absolute path, encryption backend, file
presence/readability, and effective configuration sources. They never display any
API-key characters. `--json` returns this metadata in JSON. `doctor` additionally
checks backend detection; that alone does not prove encryption authorization.
Neither command creates directories, initializes encryption keys, or rewrites the
file. `delete` checks the public format/type header without decrypting the file
and succeeds if already absent. A wrong-type or unknown-format file is not
deleted. Updating or loading a file also checks the encrypted record type. An
active process can keep using credentials already loaded in memory. This is
local deletion, not remote key revocation or guaranteed physical data erasure.

Windows uses user-scoped DPAPI with UI forbidden and application-specific entropy.
Encrypted files and newly created directories have protected ACLs granting access
only to the current user, SYSTEM, and Administrators. Linux uses an existing
`/usr/bin/systemd-creds` or `/bin/systemd-creds`, version 256 or newer, with
`--user --no-ask-password` and a fixed credential name independent of the filename.
Encryption explicitly uses the systemd host key (`--with-key=host`), not TPM
probing. The per-user credential service and noninteractive OS authorization must
already permit the operation. An explicit Linux save may initialize systemd's
host credential key if the OS permits it. The agent never installs a helper,
changes authorization policy, starts a monitoring provider, or enables GUI prompts.
If this backend is unavailable, environment-only startup remains supported.

On Linux, new directories are `0700`, files are `0600`; a write directory must be
owned by the current user and not writable by group/others. Reads reject public
permissions, foreign ownership, symlinks and extra hard links. Windows rejects
final reparse points and extra hard links. Updates serialize CLI writers using OS
locks and publish a fully written ciphertext file by replacement; encryption or
validation failure preserves the old file. Temporary files contain ciphertext
only and are cleaned up during normal error handling. No persistent lock file is
created. Files are bound to the OS encryption context; copying one to another
account or machine is not a credential migration mechanism.

Exit codes: `0` success; `2` command usage/input-mode error; `3` missing record
when required; `4` unavailable Linux encryption backend/authorization; `1` other
storage, validation or runtime failures. `status` on an absent store succeeds and
reports `exists: false`. No plaintext fallback or key-export command is provided.

References: [Windows DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
[Known Folders](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid),
[XDG paths](https://specifications.freedesktop.org/basedir/latest/),
[systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html).

## Build and verify

Use the toolchain specified by the repository's `go.mod`. Build the dedicated
entrypoint, rather than the full CLI. No Node.js, pnpm or UI build is needed.

```powershell
$env:CGO_ENABLED = '0'
go build -trimpath -buildvcs=false -ldflags '-s -w' -o .\bin\host-monitor.exe ./cmd/host-monitor
.\bin\host-monitor.exe --version
go test ./internal/hostcredentials ./internal/hostmonitor ./cmd/host-monitor
```

Linux:

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o bin/host-monitor ./cmd/host-monitor
go test ./internal/hostcredentials ./internal/hostmonitor ./cmd/host-monitor
```

Copy only the resulting executable to the target. It needs the normal OS APIs
and the current user's query permissions, but no Go/Node/Python runtime or
sidecar executables. Saved credentials add one encrypted data file. Linux saved
credentials require the existing supported systemd helper described above;
environment-only operation has no such dependency. Windows WMI/session APIs must be available for the respective
tools. The usual OpenAI polling path does not need a `cloudflared` companion.

Tests cover MCP discovery, actual host queries, bounded inputs and CPU
cancellation, subprocess stdio operation in an empty directory, and a complete
memory tool request through a local simulated tunnel service. Windows tests also
decode primary/virtual-desktop PNGs, verify image transfer over stdio and the
simulated tunnel, and check DPI restoration and GDI resource cleanup. Desktop
capture tests explicitly skip when the Windows session has no interactive
desktop; validation and error propagation still run. Set
`HOST_MONITOR_TEST_BINARY` to an absolute built executable path to run the stdio
test against that exact artifact. GitHub Actions runs native Windows and Linux
checks when changes are pushed.

Credential tests cover native Windows DPAPI roundtrips and ACLs, CLI subprocess
operations against the built executable, redaction, environment/file precedence,
corruption/size bounds, failed-update preservation, concurrent updates, and a mock
tunnel authenticated using the encrypted store. They also cover independent
admin/runtime lifecycles, wrong-type file rejection, and legacy runtime loading.
Common helper-protocol tests
verify the Linux systemd flags and stdin transfer without needing a Linux host.
Linux-native permission/path tests run on Linux; the optional native systemd
roundtrip skips unless a supported helper and a readable pre-existing host key are
available, so it does not initialize a test host's credential key implicitly.
