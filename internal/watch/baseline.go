package watch

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// BaselineFile is the name of the login baseline inside the state directory.
const BaselineFile = "login-baseline.json"

// BaselineAsideFile is the name a baseline file that is not trusted as a
// baseline (corrupt, of an unknown schema, over MaxBaselineBytes) is kept
// under. There is at most one such copy: the next reset replaces it.
const BaselineAsideFile = "login-baseline.json.bad"

// MaxBaselineBytes bounds the read of BaselineFile. It is the bound the
// rules package derives for Unmarshal (unexported there) from the same caps:
// the user and entry length bounds of 64 bytes, a user name byte at most
// doubled by escaping, 29 bytes of field syntax per user, each entry with its
// quotes and a comma, and 512 bytes of slack. A test pins that a document at
// the rules caps loads.
const MaxBaselineBytes = 512 + rules.BaselineMaxUsers*(2*64+29+rules.BaselineEntriesPerUser*(64+3))

// ErrBaselineLoad is returned by Run when the baseline file fails the trust
// checks of the state directory or cannot be read; the process must exit
// non-zero.
var ErrBaselineLoad = errors.New("watch: cannot load the login baseline")

// BaselineStore keeps the login rule's baseline in BaselineFile. The daemon
// is the only writer. Call Load once before the rules engine is built, and
// pass the store as Deps.Baseline.
type BaselineStore struct {
	dir *securefile.Dir
	b   *rules.Baseline

	loaded   bool
	fresh    bool   // no file: a new baseline whose learning starts at Load
	loadErr  error  // a trust or read failure; Run fails at start
	resetErr error  // why the file is not trusted as a baseline (the reset path)
	saved    []byte // the content on disk, as last written or read
	done     bool   // LearningDone as of the last save check

	// marshals and writes count the work of the change detection (tests).
	marshals, writes int
}

// NewBaselineStore returns a store over the state directory.
func NewBaselineStore(dir *securefile.Dir) *BaselineStore { return &BaselineStore{dir: dir} }

// Load reads BaselineFile and returns the baseline the login rule is built
// over. It never fails itself: a file that fails the trust checks, or any
// other read error, is kept and makes Run fail at start, after the error
// text went through the daemon's Clean. A missing file gives a new baseline
// whose learning starts at now. A file that is too large, corrupt or of an
// unknown schema gives a baseline whose learning phase is over (the zero
// LearningStart), and Run sets the file aside at start.
func (s *BaselineStore) Load(now time.Time) *rules.Baseline {
	s.loaded = true
	data, err := s.dir.ReadCapped(BaselineFile, MaxBaselineBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.fresh, s.b = true, rules.NewBaseline(now)
	case errors.Is(err, securefile.ErrTooLarge):
		s.resetErr = err
	case err != nil:
		s.loadErr = err
	default:
		b, uerr := rules.Unmarshal(data)
		if uerr != nil {
			s.resetErr = uerr
		} else {
			s.b, s.saved = b, data
		}
	}
	if s.b == nil {
		s.b = rules.NewBaseline(time.Time{})
	}
	s.done = s.b.LearningDone()
	return s.b
}

// setAside keeps the untrusted file as BaselineAsideFile: a hard link, so
// the file stays in place until the new baseline replaces it atomically, and
// a crash in between finds it again on the next start. A previous copy is
// removed first. Both steps go through the directory securefile opened and
// checked; the state directory is never opened again by its path, so a path
// swapped in later (by someone who can write its parent) neither receives
// the copy nor loses it. Link checks that the new name is the very file it
// examined, so no read-back of the copy is needed: a failed link fails the
// start and leaves the untrusted file where it is.
func (s *BaselineStore) setAside() error {
	if err := s.dir.Remove(BaselineAsideFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return s.dir.Link(BaselineFile, BaselineAsideFile)
}

// persist writes the baseline when its JSON form differs from the content on
// disk.
func (s *BaselineStore) persist() error {
	s.marshals++
	s.done = s.b.LearningDone()
	data, err := s.b.Marshal()
	if err != nil {
		return err
	}
	if s.saved != nil && bytes.Equal(data, s.saved) {
		return nil
	}
	s.writes++
	if err := s.dir.WriteAtomic(BaselineFile, data, MaxBaselineBytes); err != nil {
		return err
	}
	s.saved = data
	return nil
}

// startBaseline runs in start: it fails on a load error, sets an untrusted
// file aside with an input_error record and a notice, and saves the baseline
// before the stream starts, so a restart neither restarts learning nor
// reads the bad file again.
func (d *Daemon) startBaseline() error {
	s := d.deps.Baseline
	if s == nil {
		return nil
	}
	if !s.loaded {
		return fmt.Errorf("%w: the store was not loaded", ErrBaselineLoad)
	}
	if s.loadErr != nil {
		return fmt.Errorf("%w: %s", ErrBaselineLoad, d.safe(s.loadErr.Error()))
	}
	if s.resetErr != nil {
		if err := s.setAside(); err != nil {
			return fmt.Errorf("%w: cannot set the untrusted file aside: %s", ErrBaselineLoad, d.safe(err.Error()))
		}
		// The record comes before the save: a crash in between finds the
		// file again and audits it again, rather than not at all.
		reason := d.safe(s.resetErr.Error())
		if err := d.record(audit.InputError, "", "", "login baseline not trusted ("+reason+"), kept as "+BaselineAsideFile+"; a new baseline starts past its learning phase"); err != nil {
			return err
		}
		if err := d.persistBaseline(); err != nil {
			return err
		}
		d.alertEvent("baseline_reset", "keepwatch: login baseline reset",
			"The login baseline could not be trusted ("+reason+") and was kept as "+BaselineAsideFile+". The new baseline has no learning phase: every login from a source not seen since notifies.")
		return nil
	}
	if s.fresh {
		return d.persistBaseline()
	}
	return nil
}

func (d *Daemon) persistBaseline() error {
	if err := d.deps.Baseline.persist(); err != nil {
		return fmt.Errorf("watch: cannot save the login baseline: %w", err)
	}
	return nil
}

// saveBaseline runs after the signals of a line were handled and before the
// cursor moves. It looks at the baseline only when the line may have changed
// it: the learning latch flipped, or the login rule gave a signal (the rule
// adds an entry only in an Evaluate that returns a signal for it, learning
// phase included). Every other line costs a comparison and no Marshal.
func (d *Daemon) saveBaseline(sigs []event.Signal) error {
	s := d.deps.Baseline
	if s == nil {
		return nil
	}
	check := s.b.LearningDone() != s.done
	for _, sig := range sigs {
		check = check || sig.RuleID == rules.IDLoginAnomaly
	}
	if !check {
		return nil
	}
	return d.persistBaseline()
}
