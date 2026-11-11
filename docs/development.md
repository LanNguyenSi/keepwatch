# Development

Part of the [keepwatch README](../README.md).

## Build

Requires Go 1.27 or newer.

```sh
make build    # bin/keepwatch (host) and bin/keepwatch-linux-amd64, static
```

`make build` stamps the version and commit from git
(`git describe --tags --always --dirty`) and the build time, so
`keepwatch version` reports them. Release builds stamp the commit time instead
of the build time, so that the same commit builds the same bytes.

## Test

```sh
make test     # go test -race ./...
make lint     # gofmt, go vet, staticcheck
go run github.com/zricethezav/gitleaks/v8@v8.28.0 git . --config .gitleaks.toml --redact --no-banner   # secret scan, full history
```

## End-to-end tests

```sh
make e2e                              # Ubuntu 22.04 and 24.04, needs docker, jq and go
test/e2e/run.sh 24.04                 # one release
test/e2e/run.sh -update               # rewrite the golden files after a deliberate change
```

`test/e2e/` builds keepwatch for `linux/<arch of the docker daemon>`, copies it
into a fresh container of an image per release (`keepwatch-e2e:22.04`,
`keepwatch-e2e:24.04`; the Ubuntu base is pinned by digest, the packages are the
current archive) and runs `keepwatch check --format json` in five scenarios:

| Scenario | What it does | Expected exit codes |
|---|---|---|
| `hardened` | sshd with password, keyboard-interactive and root login off | 0 |
| `open` | sshd with password login, keyboard-interactive, root login and X11 forwarding on; the four `ssh.*` checks fail | 1 |
| `diff` | a run, then a TCP listener on port 8080 outside the allowlist, then a second run: `network.listeners` is a `new_failure` with an alert | 0, 1 |
| `nochange` | two runs without a change: no changes | 0, 0 |
| `reboot` | a run, then the reboot marker file, then a second run: `system.reboot_required` is a `new_failure` with an alert | 0, 1 |

`run.sh` also asserts the exit code of every run against a table of its own, independent of the golden files, and in `-update` mode it refuses to write an empty or invalid result.

The reports are compared with `test/e2e/golden/<release>/<scenario>.json`, which
also hold the exit code of every run and its stderr (empty). The container
starts sshd and fail2ban by hand, because there is no systemd.

The deployment targets are x86_64 servers. The optional workflow
`.github/workflows/e2e.yml` (manual, and on pull requests that touch `test/e2e`,
`internal`, `cmd`, `go.mod` or the Makefile; not a required check) runs the same
target on an x86_64 runner. Locally on an arm64 machine the binary is built for
arm64.

### Container limits

These are expected in the golden files, each with the reason keepwatch gives:

| Check | Status | Why |
|---|---|---|
| `services.fail2ban_active`, `services.unattended_upgrades_active` | `skipped` | there is no systemd, so no `systemctl` |
| `network.firewall_default` | `skipped` | neither nft, iptables nor ip6tables is installed in the image, a container has no firewall backend of its own |
| `updates.security_pending` | `warn` | the image carries no apt package lists (no `InRelease`), so the age of the lists is unknown; a pending update would not be seen |
| `docker.exposure` | `skipped` | no docker, no daemon configuration |
| `ssh.authorized_keys` | `skipped` | the test configuration names no expected keys |
| `certs.expiry` | `skipped` | the image holds no certificate |
| `system.reboot_required` | `skipped` (disabled in the configuration) | a container has no kernel to reboot; only the `reboot` scenario enables the check, and there the `pass` of the first run only says that the marker file is absent |

No golden file holds a `pass` that exists only because the container lacks the
thing: the checks above are `skipped` or `warn` instead. The `pass` results are
real findings about the container: the three packages are installed, the
effective sshd options, the `sshd` jail of fail2ban is running (a drop-in
points it at a plain log file instead of the journal), only sshd listens, and
the file systems are below the thresholds. `disk.usage` is configured with
thresholds of 99 and 100 percent, so a full runner cannot change the result.

### Normalisation

Before the comparison the report is rewritten in `test/e2e/normalize.jq`, and
nothing else:

| Field | Rewritten to | Why |
|---|---|---|
| `generated_at` | `<timestamp>` | the time of the run |
| `state.previous_run_at` | `<timestamp>` | the time of the previous run |
| `summary` of `packages.*_installed` (`fail2ban`, `unattended-upgrades`, `needrestart`): the version | `<version>` | apt installs the current archive version, which changes between image builds |
| `summary` of `disk.usage`: the number of file systems | `<n>` | the number of mounts depends on the container runtime |

The host name is not normalised: the container gets a fixed one. After the
rewrite, `run.sh` compares what `test/e2e/signature.jq` extracts (check ids,
kinds, statuses, severities, changes with their alert flag, subjects and
status transitions, the lists of still failing and warning checks, the counts,
the exit code, `fail_on` and the wording of each summary without its numbers, versions and placeholders) from the raw and the rewritten report, and fails
when they differ. A rewrite cannot hide a status or a check id.

## Sandbox measurement

```sh
make systemd                          # Ubuntu 22.04 and 24.04, needs docker and go
test/systemd/run.sh 24.04             # one release
test/systemd/run.sh -update           # rewrite the measured and answer files after a deliberate change
```

The installed services run in a sandbox, and `install` and `doctor` refuse every path
the sandbox would take away from them ([Where the paths must lie](install.md#where-the-paths-must-lie)).
They decide that from a table of paths. `test/systemd/` checks the table against a real
sandbox, on a container per release whose PID 1 is systemd (`keepwatch-systemd:22.04`,
`keepwatch-systemd:24.04`, privileged, the Ubuntu base pinned by digest):

1. `keepwatch install`, then a probe unit that is the installed check service with
   another program. It prints the device and inode of some two hundred directories; the
   same list is taken on the host before and after. A directory whose pair differs is
   one the service does not see (`hidden`). Inside a hidden directory the ones that are
   the host's all the same are listed too (`visible`), and so are the volatile and
   kernel file systems of the mount table (`mount`) and the links that lead into any of
   it (`link`).
2. For every directory of that list keepwatch is asked: `install` with a `state_dir`
   below it (a real install, which must refuse and create nothing), with a token file
   and with a configuration below it (where a file can be created), and `doctor` for
   units whose binary lies below it. Each must refuse and name the path.
3. The list must equal `test/systemd/measured/<release>.txt`, and the answers of step 2
   must equal `test/systemd/answers/<release>.txt`, so a question that is no longer asked
   fails too.

`go test` then ties those files to the table, in both directions
(`TestSandboxPathsFollowTheMeasuredSandbox`): every measured line is refused for every
role by an entry that says the right thing about it, and every entry of the table is
borne out by a line. So the table cannot claim that the sandbox hides a directory that
it does not hide, and a directory that a new systemd hides makes `make systemd` fail
until the table knows it.

The measurement depends on the kernel and the container runtime as well (`/proc` counts
as hidden because `ProtectKernelTunables=yes` and `ProtectControlGroups=yes` imply
`MountAPIVFS=yes`, which gives the service its own instance of it).

The workflow `.github/workflows/systemd.yml` runs `make systemd` on an x86_64 runner on
every push to `main`, on every pull request (the answers depend on the whole binary,
the configuration loader included), and once a week, so the committed files
cannot rot and a systemd that hides a new directory fails the job. The files were
first measured on arm64, and there is one set of files for every architecture. The one
difference seen between an arm64 container runtime and a real x86_64 host is the type at
`/dev`: the host mounts `devtmpfs`, the runtime a `tmpfs`. `test/systemd/mounts.awk`
writes both as `tmpfs`. That is the only thing it changes: the Go test reads the path of
a `mount` line, not its type, and one entry of the table (`/dev`) refuses it either way.
A new `hidden` or `visible` directory, a new mount or a new link still changes the file
and fails the job; a `devtmpfs` anywhere else than at `/dev` shows as a new mount.
`test/systemd/mounts_test.sh` checks this on captures of mount lists
and runs first in `make systemd`. If the first run on x86_64 (or a later runtime) shows
a difference in another line, it is a measurement to judge, not noise: look at the diff
in the log of the job, decide whether the table is wrong, and only then `-update` the
files or turn the difference into a normalisation next to the one above.
