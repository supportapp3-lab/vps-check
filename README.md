# vps-check

`vps-check` is a read-only CLI for individual developers who publish web apps to a VPS using AI or other development tools. It checks for a small set of common exposure and configuration issues and explains what it finds. It is not a complete security audit tool.

## Why vps-check?

Many solo developers can build and deploy an application without being Linux security specialists. `vps-check` helps them notice a few settings worth reviewing, such as services listening on all interfaces, Docker port bindings, and SSH authentication settings. It describes possible concerns without claiming that a service is reachable from the Internet.

## Quick Start

Build the CLI on your VPS or development machine with Go installed:

```sh
go build -o vps-check ./cmd/vps-check
./vps-check
```

The program makes no configuration changes and does not require `sudo` to run. Checks that need unavailable commands or permissions are reported as `SKIP`.

## Example Output

The following is a fictional example. It contains no VPS-specific information.

```text
VPS Check v0.1.0

[INFO] Service is listening on all interfaces
       Port: 443
       Protocols: IPv4, IPv6
       Addresses: 0.0.0.0, ::
       This service may be externally reachable depending on firewall and network configuration.

[PASS] No common datastore is listening on all interfaces

[PASS] No Docker ports bound to all interfaces detected

[PASS] SSH password authentication is disabled

[PASS] SSH root login is disabled

[PASS] UFW host firewall is active

[INFO] Nginx detected
       The server executable is available. This check does not verify whether it is configured as a reverse proxy or whether it is running.

[PASS] Automatic security updates are scheduled
```

## What It Checks

- **NET-001 — Listening ports:** Lists TCP listeners and groups IPv4/IPv6 addresses by port. Loopback-only details are shown with `--verbose` and retained in JSON.
- **NET-002 — Datastore listeners:** Warns when PostgreSQL (5432), MySQL/MariaDB (3306), Redis (6379), or MongoDB (27017) listens on all interfaces.
- **DKR-001 — Docker published ports:** Reports container ports bound to all interfaces when Docker is available.
- **SSH-001 — SSH password authentication:** Checks the effective OpenSSH setting when available.
- **SSH-002 — SSH root login:** Checks the effective OpenSSH root-login setting when available.
- **FW-001 — Host firewall:** Checks UFW state and basic nftables ruleset visibility.
- **WEB-001 — Web server executables:** Detects whether Nginx, Caddy, or Apache executables are available. It does not verify reverse-proxy configuration or service activity.
- **UPD-001 — Automatic security updates:** Checks Ubuntu apt unattended-upgrade settings and whether the `unattended-upgrades` package is installed.

## Status Meanings

- **PASS:** This specific check found the expected condition. It does not mean the whole server is safe.
- **INFO:** Informational detail that may be useful to review.
- **WARN:** A setting or condition may deserve attention.
- **HIGH:** A potentially serious condition was detected and should be reviewed.
- **SKIP:** The check could not be completed, for example because a command or required permission was unavailable.

## CLI Options

```text
vps-check [--json] [--verbose] [--version] [--no-color] [--fail-on warn|high]
```

- `--json`: Write a machine-readable JSON report, including OS information, timestamp, and findings.
- `--verbose`: Include additional evidence, including loopback-only listeners.
- `--version`: Print the tool version and exit.
- `--no-color`: Accepted for scripts; output is plain text by default.
- `--fail-on warn|high`: Return exit code 1 if a finding at or above the selected severity is present.

Exit codes are `0` when the scan completes, `1` when `--fail-on` matches a finding, and `2` when the CLI itself encounters an error.

## Supported / Tested Environments

- **Real VPS tested:** Ubuntu 22.04.5 LTS, x86_64.
- **Build targets:** Linux/amd64 and Linux/arm64 release binaries.
- Ubuntu 24.04 LTS and 26.04 LTS have not been verified on a real VPS.

The checks rely on local commands such as `ss`, `docker`, `sshd`, `ufw`, `nft`, `apt-config`, and `dpkg-query` when available.

## Safety

`vps-check` is read-only. It does not edit files or settings, restart or reconfigure services, install updates, send telemetry, contact a SaaS service, or upload results. It runs local commands to read system state. Some checks may need elevated permissions for complete results; without them, the affected checks are skipped where possible.

## Limitations

- A listener bound to `0.0.0.0` or `::` is listening on all interfaces; this does **not** prove it is reachable from the Internet.
- Provider firewalls, NAT, routing, and other external network controls are not inspected.
- This is not a complete security audit, benchmark implementation, or CVE vulnerability scanner.
- A `PASS` applies only to that specific check and does not guarantee the overall safety of a server.
- Some checks may require `sudo`; inaccessible checks are reported as `SKIP` rather than guessed.
- The only real VPS environment tested so far is Ubuntu 22.04.5 LTS on x86_64.

## Roadmap

Candidates for v0.2:

- Report pending package updates.
- Report pending security updates.
- Detect a reboot requirement using `/var/run/reboot-required`.

## Development

Run the checks before opening a pull request:

```sh
go test ./...
go vet ./...
go build ./...
```

## License

MIT. See [LICENSE](LICENSE) for the copyright notice and license text.
