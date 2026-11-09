// Package cli implements the keepwatch command line: a small dispatcher on
// top of the standard library flag package. Subcommands are stubs for now.
package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/version"
)

// Exit codes.
const (
	ExitOK             = 0
	ExitUsage          = 2
	ExitNotImplemented = 3
)

type command struct {
	name    string
	summary string
}

// commands lists the top-level commands in help order.
var commands = []command{
	{"check", "run the checks and report findings"},
	{"report", "show the result of the last run"},
	{"config", "configuration tools (config check)"},
	{"doctor", "diagnose the local environment"},
	{"init", "write an example configuration"},
	{"install", "install the scheduled run"},
	{"uninstall", "remove the scheduled run"},
	{"version", "print version, commit and build date"},
	{"help", "show this help"},
}

// Run executes the CLI with args (without the program name) and returns the
// process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return ExitOK
	case "version":
		return runVersion(rest, stdout, stderr)
	case "config":
		return runConfig(rest, stdout, stderr)
	case "check", "report", "doctor", "init", "install", "uninstall":
		return runStub(name, rest, stdout, stderr)
	}
	fmt.Fprintf(stderr, "keepwatch: unknown command %q\n", name)
	usage(stderr)
	return ExitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: keepwatch <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
}

// parse parses flags for a subcommand that takes no positional arguments.
// done is true when the caller should return code immediately.
func parse(name string, args []string, stdout, stderr io.Writer) (code int, done bool) {
	fs := flag.NewFlagSet("keepwatch "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintf(stdout, "Usage: keepwatch %s\n", name)
			return ExitOK, true
		}
		return ExitUsage, true
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "keepwatch %s: unexpected argument %q\n", name, fs.Arg(0))
		return ExitUsage, true
	}
	return 0, false
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	if code, done := parse("version", args, stdout, stderr); done {
		return code
	}
	fmt.Fprintf(stdout, "version: %s\ncommit: %s\nbuilt: %s\n", version.Version, version.Commit, version.Date)
	return ExitOK
}

func runStub(name string, args []string, stdout, stderr io.Writer) int {
	if code, done := parse(name, args, stdout, stderr); done {
		return code
	}
	fmt.Fprintf(stderr, "keepwatch %s: not implemented\n", name)
	return ExitNotImplemented
}

var configSubs = map[string]bool{"check": true}

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "-help" || args[0] == "--help") {
			fmt.Fprintln(stdout, "Usage: keepwatch config check")
			return ExitOK
		}
		fmt.Fprintln(stderr, "keepwatch config: missing subcommand (check)")
		return ExitUsage
	}
	if !configSubs[args[0]] {
		subs := make([]string, 0, len(configSubs))
		for s := range configSubs {
			subs = append(subs, s)
		}
		sort.Strings(subs)
		fmt.Fprintf(stderr, "keepwatch config: unknown subcommand %q (have: %s)\n", args[0], strings.Join(subs, ", "))
		return ExitUsage
	}
	return runStub("config "+args[0], args[1:], stdout, stderr)
}
