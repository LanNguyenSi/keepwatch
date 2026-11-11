# Contributing

## Build and test

```sh
make build     # bin/keepwatch plus a static linux/amd64 binary; needs Go
make test      # go test -race ./...; needs Go
make lint      # gofmt, go vet and staticcheck; needs Go and staticcheck
make e2e       # runs the real probes on Ubuntu 22.04 and 24.04 containers;
               # needs docker, jq and Go
make systemd   # measures the sandbox of the installed units in privileged
               # systemd containers; needs docker with privileged containers
               # and Go
```

The README describes what each of these does and what it asserts.

## Rules

- `make lint` stays clean: gofmt, `go vet` and staticcheck.
- Every behaviour change comes with a test.
- Changes to a probe or to `install`, `uninstall` and `doctor` are checked
  with the real tools in the containers (`make e2e` and `make systemd`),
  not only with unit tests.
- No shell strings anywhere in Go code, and no direct use of `os/exec`:
  programs are started only by `internal/execx`, with fixed argument lists
  and without a shell.
- keepwatch runs as root. Changes to configuration loading, path placement,
  process execution or output redaction need care and are worth calling out
  in the pull request; see [SECURITY.md](SECURITY.md).

## Pull requests

One topic per pull request. Describe what changed and how it was verified:
which targets and tests were run, and a sample of the output when the
change is visible to the operator.

## License

By contributing you agree that your contributions are licensed under the
MIT license of the project, as the rest of the code.
