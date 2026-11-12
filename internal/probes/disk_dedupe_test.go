package probes_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// miDev builds a mountinfo line with an explicit device (field 3) and root
// (field 4); mi fixes both from the id.
func miDev(id int, dev, root, point, fstype string) string {
	return fmt.Sprintf("%d 1 %s %s %s rw,relatime shared:%d - %s /dev/x rw\n", id, dev, root, point, id, fstype)
}

// Mounts that share one device are judged once: the entry with the shortest
// mount point is kept, the first one in mountinfo order on a tie.
func TestDiskUsageJudgesEachDeviceOnce(t *testing.T) {
	cases := []struct {
		name         string
		lines        []string
		wantCalled   []string
		wantSubjects []string
	}{
		{
			name: "a sandboxed service: bind mounts of the root device are not judged again",
			lines: []string{
				miDev(20, "252:1", "/", "/", "ext4"),
				miDev(21, "252:1", "/tmp", "/tmp", "ext4"),
				miDev(22, "252:1", "/var/tmp", "/var/tmp", "ext4"),
				miDev(23, "252:1", "/var/lib/keepwatch", "/var/lib/keepwatch", "ext4"),
				miDev(30, "252:15", "/", "/boot", "vfat"),
			},
			wantCalled:   []string{"/", "/boot"},
			wantSubjects: []string{"/", "/boot"},
		},
		{
			name: "the shortest mount point wins even when it comes last",
			lines: []string{
				miDev(21, "252:1", "/var/lib/keepwatch", "/var/lib/keepwatch", "ext4"),
				miDev(20, "252:1", "/", "/", "ext4"),
			},
			wantCalled:   []string{"/"},
			wantSubjects: []string{"/"},
		},
		{
			name: "one device with different roots (btrfs subvolumes): judged once, subject /",
			lines: []string{
				miDev(10, "253:0", "/", "/", "btrfs"),
				miDev(11, "253:0", "/home", "/home", "btrfs"),
			},
			wantCalled:   []string{"/"},
			wantSubjects: []string{"/"},
		},
		{
			name: "a tie: the first one in mountinfo order wins",
			lines: []string{
				miDev(10, "8:5", "/aa", "/aa", "ext4"),
				miDev(11, "8:5", "/bb", "/bb", "ext4"),
			},
			wantCalled:   []string{"/aa"},
			wantSubjects: []string{"/aa"},
		},
		{
			name:         "a device seen once: unchanged behaviour",
			lines:        []string{miDev(10, "8:1", "/", "/", "ext4")},
			wantCalled:   []string{"/"},
			wantSubjects: []string{"/"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			by := map[string]probes.Statfs{}
			for _, p := range c.wantCalled {
				by[p] = usage(95, 1)
			}
			st := &statfsMap{by: by}
			o := execDisk(diskProbe(t, nil), mountFS(c.lines...), st)
			wantStatus(t, o, result.Fail)
			if !eq(st.called, c.wantCalled) {
				t.Fatalf("statfs called for %q, want %q", st.called, c.wantCalled)
			}
			if !eq(subjects(o), c.wantSubjects) {
				t.Fatalf("subjects %v, want %v", subjects(o), c.wantSubjects)
			}
			wantSummary(t, o, fmt.Sprintf("%d of %d file system(s) at or above 90%%", len(c.wantSubjects), len(c.wantCalled)))
		})
	}
}

// When the kept mount of a device cannot be read, the other mounts of that
// device are tried, shortest first, until one reads; the device is still judged
// once, its finding keyed on the kept mount point, and the detail names the
// mount that answered.
func TestDiskUsageFallsBackToASiblingOfTheDevice(t *testing.T) {
	// one device (252:1) at / (kept, shortest), /tmp and /long/dir; a second
	// device (252:15) at /boot, read directly.
	lines := []string{
		miDev(20, "252:1", "/", "/", "ext4"),
		miDev(21, "252:1", "/tmp", "/tmp", "ext4"),
		miDev(22, "252:1", "/long/dir", "/long/dir", "ext4"),
		miDev(30, "252:15", "/", "/boot", "vfat"),
	}
	t.Run("the kept mount fails, the shortest sibling answers", func(t *testing.T) {
		st := &statfsMap{
			by:   map[string]probes.Statfs{"/tmp": usage(95, 1), "/boot": usage(1, 1)},
			errs: map[string]error{"/": errors.New("permission denied")},
		}
		o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
		wantStatus(t, o, result.Fail)
		// the kept point is tried first, then /tmp (shorter than /long/dir),
		// which answers, so /long/dir is not asked; /boot is its own device.
		if !eq(st.called, []string{"/", "/tmp", "/boot"}) {
			t.Fatalf("statfs called for %q", st.called)
		}
		if !eq(subjects(o), []string{"/"}) {
			t.Fatalf("the subject stays the kept mount point: %v", subjects(o))
		}
		d := o.Evidence[0].Detail
		if !strings.HasPrefix(d, "95% of the blocks used, 1% of the inodes used (ext4") || !strings.Contains(d, "read via /tmp)") {
			t.Fatalf("detail %q, want the fstype and read via /tmp", d)
		}
		wantSummary(t, o, "1 of 2 file system(s) at or above 90%")
	})
	t.Run("the kept and the first sibling fail, the second answers", func(t *testing.T) {
		st := &statfsMap{
			by:   map[string]probes.Statfs{"/long/dir": usage(95, 1), "/boot": usage(1, 1)},
			errs: map[string]error{"/": errors.New("permission denied"), "/tmp": errors.New("i/o error")},
		}
		o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
		wantStatus(t, o, result.Fail)
		if !eq(st.called, []string{"/", "/tmp", "/long/dir", "/boot"}) {
			t.Fatalf("statfs called for %q", st.called)
		}
		if !eq(subjects(o), []string{"/"}) || !strings.Contains(o.Evidence[0].Detail, "read via /long/dir)") {
			t.Fatalf("subjects %v, detail %q", subjects(o), o.Evidence[0].Detail)
		}
	})
	t.Run("all mounts of the device fail: an error, the kept point named, the others counted", func(t *testing.T) {
		st := &statfsMap{
			by:   map[string]probes.Statfs{"/boot": usage(95, 1)},
			errs: map[string]error{"/": errors.New("no such device"), "/tmp": errors.New("i/o error"), "/long/dir": errors.New("stale")},
		}
		o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
		wantStatus(t, o, result.Error)
		// every mount of the device was tried before the cause was reported
		if !eq(st.called, []string{"/", "/tmp", "/long/dir", "/boot"}) {
			t.Fatalf("statfs called for %q", st.called)
		}
		// the cause names the kept mount with its own error, plus how many
		// siblings failed as well; /boot still shows its failure.
		if !strings.Contains(o.Summary, "statfs /: no such device") || !strings.Contains(o.Summary, "2 other mount(s) of the device failed as well") {
			t.Fatalf("summary %q", o.Summary)
		}
		if !eq(subjects(o), []string{"/boot"}) {
			t.Fatalf("the other device's finding is kept: %v", subjects(o))
		}
	})
	t.Run("a usagePercent error on the kept mount does not fall back", func(t *testing.T) {
		// the kept mount reads but reports inconsistent numbers: that is a bad
		// read of a working path, not an unreadable one, so no sibling is tried.
		bad := probes.Statfs{Blocks: 10, Bfree: 11, Bavail: 5}
		st := &statfsMap{
			by: map[string]probes.Statfs{"/": bad, "/tmp": usage(95, 1), "/long/dir": usage(95, 1), "/boot": usage(1, 1)},
		}
		o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
		wantStatus(t, o, result.Error)
		if !eq(st.called, []string{"/", "/boot"}) {
			t.Fatalf("a usagePercent error must not fall back: called %q", st.called)
		}
		if !strings.Contains(o.Summary, "statfs /: inconsistent numbers") {
			t.Fatalf("summary %q", o.Summary)
		}
	})
	t.Run("a device with one mount and a failing statfs is unchanged", func(t *testing.T) {
		one := mountFS(miDev(10, "8:1", "/", "/", "ext4"))
		st := &statfsMap{errs: map[string]error{"/": errors.New("input/output error")}}
		o := execDisk(diskProbe(t, nil), one, st)
		wantStatus(t, o, result.Error)
		// byte-identical cause of the single-mount case: no "other mounts" tail
		if !eq(st.called, []string{"/"}) || o.Summary != "statfs /: input/output error" {
			t.Fatalf("called %q, summary %q", st.called, o.Summary)
		}
	})
}

// A kept mount whose statfs hangs times out on its own and falls back to a
// sibling that answers, so the device is still judged once, from the sibling.
func TestDiskUsageFallsBackToASiblingOnTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	// one device: the kept (shortest) mount /h hangs, the longer sibling
	// /mnt/ok answers, so the timeout on /h falls back to it.
	env := &probes.Env{
		Runner: fake.New(nil), FS: mountFS(miDev(20, "252:1", "/h", "/h", "ext4"), miDev(21, "252:1", "/mnt/ok", "/mnt/ok", "ext4")),
		StatfsTimeout: 50 * time.Millisecond,
		Statfs: func(path string) (probes.Statfs, error) {
			if path == "/h" {
				<-release
			}
			return usage(95, 1), nil
		},
	}
	done := make(chan probes.Outcome, 1)
	go func() { done <- diskProbe(t, nil).Run(context.Background(), env) }()
	select {
	case o := <-done:
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"/h"}) {
			t.Fatalf("the subject is the kept (hung) mount point: %v", subjects(o))
		}
		if d := o.Evidence[0].Detail; !strings.Contains(d, "read via /mnt/ok)") {
			t.Fatalf("the sibling that answered is named: %q", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the run hung")
	}
}
