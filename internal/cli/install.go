package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/doctor"
	"github.com/LanNguyenSi/keepwatch/internal/engine"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// hostOps is what install, uninstall and doctor take from the host. The zero
// value of a field means the real thing; tests replace opsFor.
type hostOps struct {
	fs            install.FS
	runner        execx.Runner
	geteuid       func() int
	exe           func() (string, error)
	unitDir       string
	systemdRunDir string
	sshRunDir     string
	loadConfig    func(path string) (*config.Config, error)
	state         doctor.StateProber
	resolver      doctor.Resolver
}

// opsFor builds the host access of a command; a variable so that tests can
// replace it.
var opsFor = func(e env) hostOps { return hostOps{} }

func (h hostOps) withDefaults(e env, programs []string) hostOps {
	if h.fs == nil {
		h.fs = install.OSFS{}
	}
	if h.runner == nil {
		h.runner = e.runner
	}
	if h.runner == nil {
		h.runner = execx.NewReal(append([]string{"systemctl"}, programs...))
	}
	if h.geteuid == nil {
		h.geteuid = os.Geteuid
	}
	if h.exe == nil {
		h.exe = os.Executable
	}
	if h.loadConfig == nil {
		h.loadConfig = func(p string) (*config.Config, error) { return config.Load(p) }
	}
	if h.state == nil {
		h.state = doctor.OSStateProber
	}
	return h
}

// installExit maps the error of install and uninstall to an exit code and
// prints it.
func installExit(name string, err error, stderr io.Writer) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, install.ErrRefused):
		fmt.Fprintf(stderr, "keepwatch %s: %v\n", name, err)
		return ExitUsage
	case errors.Is(err, install.ErrFailed):
		fmt.Fprintf(stderr, "keepwatch %s: %v\n", name, err)
		return ExitError
	}
	fmt.Fprintf(stderr, "keepwatch %s: internal error: %v\n", name, err)
	return ExitInternal
}

// absConfig returns the cleaned absolute path of the configuration file.
func absConfig(path string) (string, error) {
	if path == "" {
		path = config.DefaultPath
	}
	return filepath.Abs(filepath.Clean(path))
}

// confInfo is what install needs from the configuration file.
type confInfo struct {
	stateDir string
	// found is false when the file does not exist (the default state
	// directory is returned then).
	found bool
	// notify: notify.ntfy is configured.
	notify bool
}

// readConfig reads state_dir and whether notify.ntfy is configured.
func readConfig(h hostOps, path string) (confInfo, error) {
	if _, serr := h.fs.Lstat(path); serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			return confInfo{stateDir: filepath.Clean(config.DefaultStateDir)}, nil
		}
		return confInfo{}, serr
	}
	cfg, err := h.loadConfig(path)
	if err != nil {
		return confInfo{found: true}, err
	}
	return confInfo{stateDir: filepath.Clean(cfg.StateDir), found: true, notify: cfg.Notify.Ntfy != nil}, nil
}

func printConfigErr(stderr io.Writer, name string, err error) {
	var errs config.Errors
	if errors.As(err, &errs) {
		fmt.Fprintf(stderr, "keepwatch %s: the configuration is not valid, the service would fail to start:\n", name)
		for _, ce := range errs {
			fmt.Fprintln(stderr, "  "+ce.Error())
		}
		return
	}
	fmt.Fprintf(stderr, "keepwatch %s: %v\n", name, err)
}

// runInstall implements `keepwatch install`; the README has the contract.
func runInstall(e env, args []string, stdout, stderr io.Writer) int {
	var cfgPath, intervalS, weeklyS string
	var dryRun, printOnly bool
	if code, done := parse("install", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&cfgPath, "config", "", "main configuration file the service uses (default "+config.DefaultPath+")")
		fs.StringVar(&intervalS, "interval", install.DefaultInterval, "time between two checks: a number and m, h or d, from 5m to 30d")
		fs.StringVar(&weeklyS, "weekly-report", install.DefaultWeeklyReport, "day and time of the weekly report, like \"Mon 08:00\"")
		fs.BoolVar(&dryRun, "dry-run", false, "list the files and commands, change nothing")
		fs.BoolVar(&printOnly, "print", false, "print the unit files to stdout, change nothing")
	}); done {
		return code
	}
	interval, err := install.ParseInterval(intervalS)
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch install: --interval: %v\n", err)
		return ExitUsage
	}
	weekly, err := install.ParseWeekly(weeklyS)
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch install: --weekly-report: %v\n", err)
		return ExitUsage
	}
	path, err := absConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch install: --config: %v\n", err)
		return ExitUsage
	}
	h := opsFor(e).withDefaults(e, nil)
	exe, err := h.exe()
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch install: cannot tell where the keepwatch binary is: %v\n", err)
		return ExitInternal
	}
	ci, err := readConfig(h, path)
	if err != nil {
		printConfigErr(stderr, "install", err)
		return ExitUsage
	}
	spec := install.Spec{Binary: exe, ConfigPath: path, StateDir: ci.stateDir, Notify: ci.notify, Interval: interval, Weekly: weekly}

	if printOnly {
		files, err := install.Render(spec)
		if err != nil {
			fmt.Fprintf(stderr, "keepwatch install: %v\n", err)
			return ExitUsage
		}
		for i, f := range files {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "# ===== %s =====\n%s", f.Name, f.Content)
		}
		return ExitOK
	}
	deps := install.Deps{FS: h.fs, Runner: h.runner, Geteuid: h.geteuid, UnitDir: h.unitDir, SystemdRunDir: h.systemdRunDir, Out: stdout}
	err = install.Install(e.ctx, deps, install.InstallOptions{Spec: spec, DryRun: dryRun, ConfigFound: ci.found})
	return installExit("install", err, stderr)
}

// runUninstall implements `keepwatch uninstall`.
func runUninstall(e env, args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	var dryRun, purge bool
	if code, done := parse("uninstall", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&cfgPath, "config", "", "main configuration file, used to find what --purge removes (default "+config.DefaultPath+")")
		fs.BoolVar(&dryRun, "dry-run", false, "list the files and commands, change nothing")
		fs.BoolVar(&purge, "purge", false, "also remove keepwatch's configuration and state")
	}); done {
		return code
	}
	path, err := absConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch uninstall: --config: %v\n", err)
		return ExitUsage
	}
	h := opsFor(e).withDefaults(e, nil)
	deps := install.Deps{FS: h.fs, Runner: h.runner, Geteuid: h.geteuid, UnitDir: h.unitDir, SystemdRunDir: h.systemdRunDir, Out: stdout}
	err = install.Uninstall(e.ctx, deps, install.UninstallOptions{
		DryRun: dryRun, Purge: purge, ConfigPath: path, ConfigExplicit: cfgPath != "",
		DefaultConfigPath: config.DefaultPath, DefaultStateDir: filepath.Clean(config.DefaultStateDir),
		StateDirOf: func(p string) (string, bool, error) {
			ci, err := readConfig(h, p)
			return ci.stateDir, ci.found, err
		},
	})
	return installExit("uninstall", err, stderr)
}

// sendTestFinding delivers one short test message through the configured
// channel and says what happened as a finding of doctor. It writes no state:
// nothing here touches state_dir.
func sendTestFinding(e env, h hostOps, path string) doctor.Finding {
	fail := func(format string, a ...any) doctor.Finding {
		return doctor.Finding{Level: doctor.Problem, Area: "send-test", Message: fmt.Sprintf(format, a...)}
	}
	cfg, err := h.loadConfig(path)
	if err != nil {
		return fail("no test message sent: the configuration is not valid (see config above)")
	}
	ntf, err := e.newNotifier(cfg)
	if err != nil {
		return fail("no test message sent: %v", err)
	}
	red, err := redact.New(cfg.Redact.Patterns)
	if err != nil {
		return fail("no test message sent: %v", err)
	}
	host, herr := e.hostname()
	if herr != nil {
		host = "unknown"
	}
	msg := notify.Message{
		Title:    "keepwatch test message",
		Body:     red.Clean("This is a test from \"keepwatch doctor --send-test\" on " + host + ". Nothing is wrong; if you read this, delivery works."),
		Priority: notify.PriorityOf(result.Low),
		Tags:     []string{"keepwatch"},
	}
	if err := ntf.Send(e.ctx, msg); err != nil {
		return fail("the test message was not delivered: %s", red.Clean(err.Error()))
	}
	return doctor.Finding{Level: doctor.OK, Area: "send-test", Message: "the test message was delivered"}
}

// runDoctor implements `keepwatch doctor`.
func runDoctor(e env, args []string, stdout, stderr io.Writer) int {
	e = e.withDefaults()
	var cfgPath string
	var send bool
	if code, done := parse("doctor", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&cfgPath, "config", "", "main configuration file (default "+config.DefaultPath+")")
		fs.BoolVar(&send, "send-test", false, "deliver one test message through the configured ntfy channel (writes no state)")
	}); done {
		return code
	}
	cat := e.catalog
	if cat == nil {
		var err error
		if cat, err = catalog.Base(); err != nil {
			fmt.Fprintf(stderr, "keepwatch doctor: %v\n", err)
			return ExitInternal
		}
	}
	progs := engine.Programs(cat)
	h := opsFor(e).withDefaults(e, progs)
	res := h.resolver
	if res == nil {
		res = execx.NewReal(progs)
	}
	path, err := absConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch doctor: --config: %v\n", err)
		return ExitUsage
	}
	rep := doctor.Run(e.ctx, doctor.Deps{
		ConfigPath: path, LoadConfig: h.loadConfig, Catalog: cat, Resolver: res, Runner: h.runner,
		FS: h.fs, Geteuid: h.geteuid, State: h.state, UnitDir: h.unitDir, SystemdRunDir: h.systemdRunDir, SSHRunDir: h.sshRunDir,
	})
	if send {
		rep.Findings = append(rep.Findings, sendTestFinding(e, h, path))
	}
	rep.Write(stdout)
	if rep.Problems() > 0 {
		return ExitError
	}
	return ExitOK
}
