// Command keepwatch is a small, self-hosted guardian for Linux servers.
package main

import (
	"os"

	"github.com/LanNguyenSi/keepwatch/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
