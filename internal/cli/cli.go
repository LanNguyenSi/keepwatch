// Package cli implements the keepwatch command line: a small dispatcher on
// top of the standard library flag package. Subcommands are stubs for now.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/version"
)

// Exit codes. ExitInternal and ExitNotImplemented are both 3.
const (
	ExitOK             = 0
	ExitError          = 1
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
	e, stop := prodEnv()
	defer stop()
	return dispatch(e, args, stdout, stderr)
}

func dispatch(e env, args []string, stdout, stderr io.Writer) int {
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
	case "init":
		return runInit(rest, stdout, stderr)
	case "check":
		return runCheck(e, rest, stdout, stderr)
	case "report", "doctor", "install", "uninstall":
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

// parse parses flags for a subcommand. define adds the subcommand's own
// flags when not nil. done is true when the caller should return code
// immediately.
func parse(name string, args []string, stdout, stderr io.Writer, define func(*flag.FlagSet)) (code int, done bool) {
	fs := flag.NewFlagSet("keepwatch "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {} // errors are printed by flag; -h prints our own usage
	if define != nil {
		define(fs)
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintf(stdout, "Usage: keepwatch %s\n", name)
			fs.SetOutput(stdout)
			fs.PrintDefaults()
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
	if code, done := parse("version", args, stdout, stderr, nil); done {
		return code
	}
	fmt.Fprintf(stdout, "version: %s\ncommit: %s\nbuilt: %s\n", version.Version, version.Commit, version.Date)
	return ExitOK
}

func runStub(name string, args []string, stdout, stderr io.Writer) int {
	if code, done := parse(name, args, stdout, stderr, nil); done {
		return code
	}
	fmt.Fprintf(stderr, "keepwatch %s: not implemented\n", name)
	return ExitNotImplemented
}

// runConfigCheck loads the configuration and reports every problem it
// finds: exit 0 and one summary line when valid, exit 1 and one
// file:line: message per problem otherwise, exit 2 on usage errors.
func runConfigCheck(args []string, stdout, stderr io.Writer) int {
	var path string
	if code, done := parse("config check", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&path, "config", "", "main configuration file (default "+config.DefaultPath+")")
	}); done {
		return code
	}
	cfg, err := config.Load(path)
	if err != nil {
		var errs config.Errors
		if errors.As(err, &errs) {
			for _, e := range errs {
				fmt.Fprintln(stderr, e.Error())
			}
		} else {
			fmt.Fprintln(stderr, err)
		}
		return ExitError
	}
	fmt.Fprintf(stdout, "config ok: %s (+%d conf.d files)\n", cfg.Sources.Main, len(cfg.Sources.ConfD))
	return ExitOK
}

// runInit writes the embedded example configuration.
func runInit(args []string, stdout, stderr io.Writer) int {
	var path string
	var force bool
	if code, done := parse("init", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&path, "config", "", "main configuration file to write (default "+config.DefaultPath+")")
		fs.BoolVar(&force, "force", false, "overwrite an existing file")
	}); done {
		return code
	}
	if path == "" {
		path = config.DefaultPath
	}
	if err := config.WriteExample(path, force); err != nil {
		fmt.Fprintf(stderr, "keepwatch init: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "wrote %s\n", path)
	return ExitOK
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
	return runConfigCheck(args[1:], stdout, stderr)
}
