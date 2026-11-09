# keepwatch

A small, self-hosted guardian for Linux servers.

Status: pre-MVP, under active development. Not ready for use.

keepwatch checks the security posture of a host (for example: is fail2ban
running, is SSH password login disabled, which ports are listening), reports
only what changed since the last run, and sends the result to a notification
channel. Later stages add log-based detection, optional triage with a local
LLM, and policy-gated, human-approved actions with a tamper-evident audit log.

## Build

Requires Go 1.27 or newer.

```sh
make build    # bin/keepwatch (host) and bin/keepwatch-linux-amd64, static
```

## Test

```sh
make test     # go test -race ./...
make lint     # gofmt, go vet, staticcheck
```

## Configuration

The main file is `/etc/keepwatch/keepwatch.yaml` (override with
`--config`). Every `*.yaml` in a `conf.d` directory next to it is loaded
in lexicographic order and merged in: mappings merge per key (later
files win), sequences such as `exceptions` and `listeners.allow` append,
and scalars are replaced by the later file. A missing `conf.d` is fine;
a missing main file is an error. Unknown keys, wrong types and out-of-range
values are rejected, each error naming `file:line`.

More rules, all reported with `file:line`:

- The root of every file must be a mapping (an empty or null document
  is treated as empty; a file never replaces another file's root).
- A key repeated within the same mapping of the same file is an error
  at any depth; the same key set again by a later file is an override.
- Scalars are matched by YAML type: `enabled` is true/false, `port` is
  an integer, strings are strings (quoted `"22"` is not a port),
  `expires` is a `YYYY-MM-DD` date. A null (`~`) value counts as absent
  for optional fields and is an error for required ones.
- `*.yml` in `conf.d` is an error; use the `.yaml` extension.
- Because keepwatch runs as root, loaded files and the `conf.d`
  directory must not be symlinks, must be owned by root or the running
  user, and must not be writable by group or other (mode 0644 or
  stricter for files). Symlinks are never followed and checks run on
  the open file itself.
- `notify.ntfy.url` is required when `notify.ntfy` is set (https, or
  http only for loopback; a URL port must be 1-65535).
- `notify.ntfy.token_file` must be a regular file, at most 4096 bytes,
  mode 0600 or stricter, owned by the running user; it is validated
  without reading and re-checked when the token is read, so swapping
  the path after startup cannot redirect the secret.
- `keepwatch init` writes the example file atomically (temp file +
  rename, mode 0640) and refuses to follow symlinks; `--force` only
  replaces a regular file.

```sh
keepwatch init --config /etc/keepwatch/keepwatch.yaml   # write a commented example
keepwatch config check --config /etc/keepwatch/keepwatch.yaml
```

## Status

Pre-MVP. The command line skeleton, the program execution layer and the
strict configuration loader exist; `config check` and `init` are
implemented, while the commands (`check`, `report`, `doctor`, `install`,
`uninstall`) are stubs that exit with status 3.

## License

MIT, see [LICENSE](LICENSE).
