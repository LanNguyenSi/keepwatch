package probes_test

import (
	"fmt"
	"testing"

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
