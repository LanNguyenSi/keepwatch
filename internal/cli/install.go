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

// stateDirOf reads state_dir from the configuration. found is false when the
// file does not exist (the default state directory is returned then).
func stateDirOf(h hostOps, path string) (dir string, found bool, err error) {
	if _, serr := h.fs.Lstat(path); serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			return filepath.Clean(config.DefaultStateDir), false, nil
		}
		return "", false, serr
	}
	cfg, err := h.loadConfig(path)
	if err != nil {
		return "", true, err
	}
	return filepath.Clean(cfg.StateDir), true, nil
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
	stateDir, found, err := stateDirOf(h, path)
	if err != nil {
		printConfigErr(stderr, "install", err)
		return ExitUsage
	}
	spec := install.Spec{Binary: exe, ConfigPath: path, StateDir: stateDir, Interval: interval, Weekly: weekly}

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
	err = install.Install(e.ctx, deps, install.InstallOptions{Spec: spec, DryRun: dryRun, ConfigFound: found})
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
		StateDirOf: func(p string) (string, bool, error) { return stateDirOf(h, p) },
	})
	return installExit("uninstall", err, stderr)
}

// sendTest is the seam for `doctor --send-test`: it delivers a test
// notification through the configured channel. Until the notifier exists it
// reports errSendTestUnavailable.
var sendTest = func(env, *config.Config) error { return errSendTestUnavailable }

var errSendTestUnavailable = errors.New("--send-test is not available yet: the notifier is not implemented in this version")

// runDoctor implements `keepwatch doctor`.
func runDoctor(e env, args []string, stdout, stderr io.Writer) int {
	var cfgPath string
	var send bool
	if code, done := parse("doctor", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&cfgPath, "config", "", "main configuration file (default "+config.DefaultPath+")")
		fs.BoolVar(&send, "send-test", false, "deliver a test notification through the configured channel")
	}); done {
		return code
	}
	if send {
		// The seam decides before anything is checked: until it exists, the
		// flag is a usage error, not a half-done diagnosis.
		if err := sendTest(e, nil); errors.Is(err, errSendTestUnavailable) {
			fmt.Fprintf(stderr, "keepwatch doctor: %v\n", err)
			return ExitUsage
		}
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
	rep.Write(stdout)
	if rep.Problems() > 0 {
		return ExitError
	}
	return ExitOK
}
