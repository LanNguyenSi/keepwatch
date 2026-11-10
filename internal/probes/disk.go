package probes

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

const (
	mountinfoFile = "/proc/self/mountinfo"
	maxMountinfo  = 8 << 20
)

// defaultStatfsTimeout bounds one statfs call: a file system that hangs must
// not hang the run.
const defaultStatfsTimeout = 10 * time.Second

// diskUsage checks how full the mounted file systems are, for blocks and for
// inodes.
//
// Parameters:
//
//	warn_percent  (integer 1 to 100, default 80)  usage at or above which the
//	              status is warn
//	fail_percent  (integer 1 to 100, default 90)  usage at or above which the
//	              status is fail; warn_percent must not be higher
//	fstypes       (list of file system types, default ext4, xfs, btrfs, vfat,
//	              zfs)  which mounts are examined
//
// List semantics: "fstypes" under checks.<id>.params REPLACES the default, it
// is not appended to it (so "fstypes: [ext4]" drops xfs and the others). Lists
// from conf.d drop-ins are already appended to the main file's list when the
// config is loaded.
//
// The mounts come from /proc/self/mountinfo, whose octal escapes (\040 for a
// blank, \012 for a newline, \134 for a backslash) in the mount point are
// decoded. Only mounts whose type is in "fstypes" are examined: a network file
// system (nfs, cifs, fuse.sshfs) that hangs would otherwise block the run, and
// pseudo file systems have no meaningful usage. A line of mountinfo that does
// not parse is error. For a mount point that appears more than once the last
// entry is the visible one. Usage comes from statfs(2) on the mount point
// (injected, Env.Statfs), with the timeout of Env.StatfsTimeout (default 10
// seconds) per call; a mount that cannot be read, times out or reports
// inconsistent numbers is error with the findings of the others kept.
//
// Usage is computed like df: used blocks over used plus the blocks available
// to unprivileged users, rounded up, and used inodes over all inodes (a file
// system without a fixed inode count, such as btrfs and vfat, has no inode
// check). The highest of the two decides. A mount at or above fail_percent is
// a fail, one at or above warn_percent a warn, subject = the mount point,
// detail the percentages. With a fail the warnings are counted in the summary
// and carried in Outcome.Warnings (an exception for every failing mount leaves
// a warn). No mount of a checked type means skipped.
type diskUsage struct{}

func (diskUsage) Name() string       { return "disk_usage" }
func (diskUsage) Programs() []string { return nil }

var fstypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,31}$`)

func (diskUsage) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	warn := p.integer("warn_percent", 80, 1, 100)
	fail := p.integer("fail_percent", 90, 1, 100)
	types := p.strList("fstypes", false, true, []string{"ext4", "xfs", "btrfs", "vfat", "zfs"}, func(s string) error {
		if !fstypePattern.MatchString(s) {
			return fmt.Errorf("file system type %q does not match %s", s, fstypePattern)
		}
		return nil
	})
	if err := p.err(); err != nil {
		return nil, err
	}
	if warn > fail {
		return nil, fmt.Errorf("warn_percent (%d) must not be higher than fail_percent (%d)", warn, fail)
	}
	set := map[string]bool{}
	for _, t := range types {
		set[t] = true
	}
	return diskProbe{warn: warn, fail: fail, types: set}, nil
}

type diskProbe struct {
	warn, fail int
	types      map[string]bool
}

type mount struct{ point, fstype string }

func (d diskProbe) Run(ctx context.Context, env *Env) Outcome {
	b, err := env.FS.ReadFile(mountinfoFile, maxMountinfo)
	if err != nil {
		return *errorOutcome("cannot read %s: %s", mountinfoFile, clean(err.Error(), 120))
	}
	mounts, err := parseMountinfo(string(b))
	if err != nil {
		return *errorOutcome("%s: %v", mountinfoFile, err)
	}
	var wanted []mount
	for _, m := range mounts {
		if d.types[m.fstype] {
			wanted = append(wanted, m)
		}
	}
	if len(wanted) == 0 {
		return Outcome{Status: result.Skipped, Summary: "no mounted file system of the checked types, check skipped"}
	}

	timeout := env.StatfsTimeout
	if timeout <= 0 {
		timeout = defaultStatfsTimeout
	}
	var fails, warns []result.Evidence
	var causes []string
	for _, m := range wanted {
		st, serr := statfsWithTimeout(ctx, env.statfs(), m.point, timeout)
		if serr != nil {
			causes = append(causes, fmt.Sprintf("statfs %s: %s", clean(m.point, 80), clean(serr.Error(), 100)))
			continue
		}
		blocks, inodes, serr := usagePercent(st)
		if serr != nil {
			causes = append(causes, fmt.Sprintf("statfs %s: %v", clean(m.point, 80), serr))
			continue
		}
		worst := blocks
		detail := fmt.Sprintf("%d%% of the blocks used", blocks)
		if inodes >= 0 {
			detail += fmt.Sprintf(", %d%% of the inodes used", inodes)
			worst = max(worst, inodes)
		}
		ev := result.Evidence{Subject: clean(m.point, 200), Detail: fmt.Sprintf("%s (%s)", detail, m.fstype)}
		switch {
		case worst >= d.fail:
			fails = append(fails, ev)
		case worst >= d.warn:
			warns = append(warns, ev)
		}
	}
	if len(causes) > 0 {
		if len(causes) > maxPartialSubjects {
			causes = append(causes[:maxPartialSubjects], fmt.Sprintf("and %d more mounts could not be read", len(causes)-maxPartialSubjects))
		}
		shown, _, set := limitEvidence(fails)
		o := partialError(causes, fails)
		o.Evidence, o.Set = shown, set
		return o
	}
	switch {
	case len(fails) > 0:
		shown, hidden, set := limitEvidence(fails)
		s := fmt.Sprintf("%d of %d file system(s) at or above %d%%: %s", len(fails), len(wanted), d.fail, subjectList(shown, 5))
		if len(warns) > 0 {
			s += fmt.Sprintf("; %d more at or above %d%%", len(warns), d.warn)
		}
		shownWarns, _, warnSet := limitEvidence(warns)
		return Outcome{Status: result.Fail, Summary: s + moreNote(hidden), Evidence: shown, Set: set, Warnings: shownWarns, WarningsSet: warnSet}
	case len(warns) > 0:
		shown, hidden, set := limitEvidence(warns)
		return Outcome{
			Status:   result.Warn,
			Summary:  fmt.Sprintf("%d of %d file system(s) at or above %d%%: %s", len(warns), len(wanted), d.warn, subjectList(shown, 5)) + moreNote(hidden),
			Evidence: shown,
			Set:      set,
		}
	}
	return Outcome{Status: result.Pass, Summary: fmt.Sprintf("%d file system(s) below %d%%", len(wanted), d.warn)}
}

// statfsWithTimeout calls f in its own goroutine and gives up after timeout. A
// call that never returns leaks its goroutine until the process ends, which is
// the price of not hanging the run.
func statfsWithTimeout(ctx context.Context, f StatfsFunc, path string, timeout time.Duration) (Statfs, error) {
	type reply struct {
		st  Statfs
		err error
	}
	ch := make(chan reply, 1)
	go func() {
		st, err := f(path)
		ch <- reply{st, err}
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.st, r.err
	case <-t.C:
		return Statfs{}, errors.New("timed out")
	case <-ctx.Done():
		return Statfs{}, ctx.Err()
	}
}

// usagePercent returns the block usage and, when the file system has a fixed
// inode count, the inode usage (-1 otherwise), both rounded up like df.
func usagePercent(s Statfs) (blocks, inodes int, err error) {
	if s.Bfree > s.Blocks || s.Bavail > s.Bfree || s.Ffree > s.Files {
		return 0, 0, errors.New("inconsistent numbers")
	}
	used := s.Blocks - s.Bfree
	if denom := used + s.Bavail; denom > 0 {
		blocks = ceilPercent(used, denom)
	}
	inodes = -1
	if s.Files > 0 {
		inodes = ceilPercent(s.Files-s.Ffree, s.Files)
	}
	return blocks, inodes, nil
}

// ceilPercent returns ceil(100*part/whole) for part <= whole, without
// overflow.
func ceilPercent(part, whole uint64) int {
	hi, lo := bits.Mul64(part, 100)
	q, r := bits.Div64(hi, lo, whole)
	if r > 0 {
		q++
	}
	return int(q)
}

// parseMountinfo reads /proc/self/mountinfo. For a mount point that appears
// several times only the last entry is kept, in order of first appearance.
func parseMountinfo(content string) ([]mount, error) {
	var out []mount
	index := map[string]int{}
	for i, line := range strings.Split(content, "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, " ")
		sep := -1
		for j := 6; j < len(f); j++ {
			if f[j] == "-" {
				sep = j
				break
			}
		}
		if sep < 0 || len(f) < sep+4 || len(f) < 7 {
			return nil, fmt.Errorf("line %d is not a mountinfo line", i+1)
		}
		point, err := unescapeMount(f[4])
		if err != nil || !strings.HasPrefix(point, "/") {
			return nil, fmt.Errorf("line %d has an unusable mount point", i+1)
		}
		m := mount{point: point, fstype: f[sep+1]}
		if j, ok := index[point]; ok {
			out[j] = m
			continue
		}
		index[point] = len(out)
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, errors.New("no mounts listed")
	}
	return out, nil
}

// unescapeMount decodes the octal escapes of mountinfo (\040, \011, \012,
// \134): a backslash followed by three octal digits is one byte; any other use
// of a backslash is an error.
func unescapeMount(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", errors.New("bad escape")
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", errors.New("bad escape")
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String(), nil
}
