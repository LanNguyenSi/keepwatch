package install_test

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/install"
)

func firstUnitWrite(log []string) int {
	for i, l := range log {
		if strings.HasPrefix(l, "write "+unitDir+"/") {
			return i
		}
	}
	return -1
}

func noUnits(t *testing.T, r *rig) {
	t.Helper()
	for _, n := range install.UnitNames {
		if r.fs.Exists(unitPath(n)) {
			t.Errorf("%s was written", n)
		}
	}
	if m := r.sd.Mutations(); len(m) != 0 {
		t.Errorf("systemctl ran: %v", m)
	}
}

// A real install proves that state_dir is writable before the first unit is
// written, with the probe doctor runs, and leaves no probe file.
func TestInstallProbesTheStateDirectoryBeforeAnyUnit(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "state_dir created by this run"
		if existing {
			name = "state_dir found"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig()
			if existing {
				r.fs.AddDir(stateDir, 0o700, 0)
			}
			if err := r.install(t, install.InstallOptions{}); err != nil {
				t.Fatalf("%v\n%s", err, r.out)
			}
			created, removed := probes(r.fs.Log)
			if created != 1 || removed != 1 {
				t.Fatalf("probe files created %d, removed %d, want 1 and 1: %v", created, removed, r.fs.Log)
			}
			pi, ui := -1, firstUnitWrite(r.fs.Log)
			for i, l := range r.fs.Log {
				if strings.HasPrefix(l, "write "+stateDir+"/"+install.ProbePrefix) {
					pi = i
				}
			}
			if pi < 0 || ui < 0 || pi > ui {
				t.Errorf("the probe (log entry %d) does not come before the first unit (%d): %v", pi, ui, r.fs.Log)
			}
		})
	}
}

// A second run, with nothing to change, probes too: the host can have changed.
func TestInstallProbesAgainWhenNothingChanges(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	r.fs.Log = nil
	r.fs.ReadOnly[stateDir] = true
	err := r.install(t, install.InstallOptions{})
	if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "read-only file system") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(r.out.String(), "already installed") {
		t.Errorf("says it is already installed:\n%s", r.out)
	}
}

// A state_dir on a read-only file system is refused with the sentence doctor
// prints, exit class "refused", and nothing but that directory exists.
func TestInstallRefusesAStateDirectoryThatCannotBeWritten(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		r := newRig()
		r.fs.AddDir(stateDir, 0o700, 0)
		r.fs.ReadOnly[stateDir] = true
		err := r.install(t, install.InstallOptions{})
		if !errors.Is(err, install.ErrRefused) {
			t.Fatalf("err = %v, want a refusal", err)
		}
		for _, s := range []string{"state_dir " + stateDir + " is not usable, checks would exit 3: not writable: ", "read-only file system", syscall.EROFS.Error()} {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("err %q lacks %q", err, s)
			}
		}
		if len(r.fs.Log) != 0 {
			t.Errorf("a refused install changed the file system: %v", r.fs.Log)
		}
		noUnits(t, r)
	})
	t.Run("created by this run stays, empty, and a second run goes on", func(t *testing.T) {
		r := newRig()
		// The directory does not exist yet, so mkdir works; the file system
		// under it is read-only for files.
		r.fs.ReadOnly[stateDir] = true
		err := r.install(t, install.InstallOptions{})
		if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "not writable") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if !r.fs.Exists(stateDir) || len(r.fs.Log) != 1 || r.fs.Log[0] != "mkdir "+stateDir {
			t.Errorf("want the created, empty %s and nothing else, log %v", stateDir, r.fs.Log)
		}
		noUnits(t, r)
		// Fixed: the next run finds the directory, probes, installs.
		delete(r.fs.ReadOnly, stateDir)
		if err := r.install(t, install.InstallOptions{}); err != nil {
			t.Fatalf("second run: %v\n%s", err, r.out)
		}
		if !r.fs.Exists(unitPath(install.CheckTimer)) {
			t.Error("the second run wrote no unit")
		}
	})
	t.Run("a state_dir that cannot be opened is a refusal too", func(t *testing.T) {
		r := newRig()
		r.fs.AddDir(stateDir, 0o700, 0)
		r.fs.FailOpenDir[stateDir] = errors.New("input/output error")
		err := r.install(t, install.InstallOptions{})
		if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "not writable: input/output error") {
			t.Fatalf("err = %v", err)
		}
		noUnits(t, r)
	})
}

// --dry-run and --print stay free of side effects: they do not probe, and the
// dry run says so.
func TestDryRunAndPrintDoNotProbeTheStateDirectory(t *testing.T) {
	r := newRig()
	r.fs.AddDir(stateDir, 0o700, 0)
	r.fs.ReadOnly[stateDir] = true
	if err := r.install(t, install.InstallOptions{DryRun: true}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("dry run changed the file system: %v", r.fs.Log)
	}
	if !strings.Contains(r.out.String(), "--dry-run does not probe whether "+stateDir+" is writable") {
		t.Errorf("the dry run does not say that it does not probe:\n%s", r.out)
	}
	if _, err := install.Preflight(r.fs, install.InstallOptions{Spec: spec(t), ConfigFound: true}); err != nil {
		t.Errorf("Preflight (--print): %v", err)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("Preflight changed the file system: %v", r.fs.Log)
	}
	// A real run does not print the note.
	r2 := newRig()
	if err := r2.install(t, install.InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r2.out.String(), "does not probe") {
		t.Errorf("a real install prints the dry-run note:\n%s", r2.out)
	}
}
