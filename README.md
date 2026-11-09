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

## Status

Pre-MVP. The command line skeleton and the program execution layer exist;
the commands (`check`, `report`, `config check`, `doctor`, `init`, `install`,
`uninstall`) are stubs that exit with status 3.

## License

MIT, see [LICENSE](LICENSE).
