# keepwatch

A small, self-hosted guardian for Linux servers.

Status: stage 0 is usable: posture checks, reports of what changed, ntfy
notifications, a weekly report, and a systemd install with a hardened
sandbox. keepwatch is pre-1.0, so command-line flags, configuration keys and
the JSON report may still change between minor versions.

keepwatch checks the security posture of a host (for example: is fail2ban
running, is SSH password login disabled, which ports are listening), reports
only what changed since the last run, and sends the result to a notification
channel. Later stages add log-based detection, optional triage with a local
LLM, and policy-gated, human-approved actions with a tamper-evident audit log.

## Requirements

A Linux server with systemd. The checks and `install` run as root.
Tested on Ubuntu 22.04 and 24.04; releases ship static binaries for amd64 and
arm64. Building from source needs Go 1.27 or newer.

## Quick start

Install a release on the server (the full steps, with the verification of the
download, are in [docs/install.md](docs/install.md)), then:

```sh
# download the archive and checksums.txt from the releases page, then:
sha256sum -c checksums.txt --ignore-missing
tar -xzf keepwatch_0.1.0_linux_amd64.tar.gz keepwatch
sudo install -o root -g root -m 0755 keepwatch /usr/local/bin/keepwatch
sudo keepwatch init                 # write an example configuration
sudo keepwatch config check         # validate it
sudo keepwatch install              # install the systemd units
sudo keepwatch doctor               # check the installation
```

## Usage

- `keepwatch check`: run the checks and report what changed since the last run.
- `keepwatch report --weekly`: send the weekly report.
- `keepwatch config check`: load the configuration and report every error.
- `keepwatch init`: write an example configuration.
- `keepwatch install`: install and start the systemd units for scheduled runs.
- `keepwatch uninstall`: remove the units (`--purge` also removes the state).
- `keepwatch doctor`: check that the installation works as intended.
- `keepwatch version`: print the version and commit.

Every command takes `--help` for its flags; the details of each are in the
[documentation](#documentation).

## Documentation

The reference material lives in `docs/`:

- [docs/configuration.md](docs/configuration.md): the configuration file, its keys and the `conf.d` drop-ins.
- [docs/checks.md](docs/checks.md): every check, what it reads and what it reports.
- [docs/running.md](docs/running.md): `check` in detail: exit codes, the comparison with the last run, state, notifications, the weekly report, history, output safety and redaction.
- [docs/install.md](docs/install.md): installing from a release, and the scheduled runs: `install`, `uninstall`, `doctor`, the paths and the hardening of the units.
- [docs/development.md](docs/development.md): build, test, end-to-end tests and the sandbox measurement.
- [CONTRIBUTING.md](CONTRIBUTING.md): rules for changes.
- [SECURITY.md](SECURITY.md): reporting a vulnerability.

## Roadmap

The later stages below are planned, not built, and carry no dates:

- Log-based detection: watch the host's logs for attack patterns, not only
  the posture of the host.
- Optional triage with a local LLM: a local model may summarize and rank the
  findings, with no data leaving the host.
- Policy-gated, human-approved actions: keepwatch may propose a fix, a
  policy decides whether it may propose it at all, and nothing runs without
  a person approving it.
- A tamper-evident audit log shipped off the host: findings and actions
  recorded in a log copied off the host, so it cannot be rewritten quietly.

## Development

```sh
make build    # bin/keepwatch (host) and bin/keepwatch-linux-amd64, static
make test     # go test -race ./...
make lint     # gofmt, go vet, staticcheck
```

See [docs/development.md](docs/development.md) for what each target does and
[CONTRIBUTING.md](CONTRIBUTING.md) for the rules.

## Status

Stage 0 is complete as listed at the top of this file: posture checks, change
reports, ntfy notifications, the weekly report, and the systemd install with
a hardened sandbox. Concretely: the command line skeleton, the program
execution layer, the strict configuration loader, the check engine with twelve
check kinds, the state of the last run, the comparison, the text, JSON and
Markdown reports, the ntfy notification and the weekly report exist; `check`,
`report --weekly`, `config check`, `init`, `install`, `uninstall` and `doctor`
are implemented, while `report` without `--weekly` is still a stub that exits
with status 3. The later stages are listed in the [Roadmap](#roadmap).

## License

MIT, see [LICENSE](LICENSE).
