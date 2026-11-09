//go:build unix

package probes_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// A certbot style layout on the real file system: live/ holds links into
// archive/.
func TestCertExpiryFollowsLinksIntoATrustedArchive(t *testing.T) {
	b := certTree(t)
	archive := filepath.Join(b, "archive/example/fullchain1.pem")
	if err := os.WriteFile(archive, []byte(pemCert(t, "example.test", t0.Add(days(5)))), 0o644); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(b, "live/example/fullchain.pem")
	p := certProbe(t, map[string]any{"globs": []any{filepath.Join(b, "live/*/fullchain.pem")}})
	fsys := trustedFS(t, b)

	o := execAt(p, fake.New(nil), fsys, t0)
	wantStatus(t, o, result.Fail)
	if !eq(subjects(o), []string{live}) || !strings.Contains(o.Evidence[0].Detail, ", file "+archive[:60]) {
		t.Fatalf("evidence %+v", o.Evidence)
	}

	// somebody else can write to the archive directory: the file is not read
	if err := os.Chmod(filepath.Dir(archive), 0o777); err != nil {
		t.Fatal(err)
	}
	o = execAt(p, fake.New(nil), fsys, t0)
	wantStatus(t, o, result.Error)
	wantSummary(t, o, "writable by group or others")
	if len(o.Evidence) != 0 {
		t.Fatalf("a refused file must not produce a finding: %+v", o.Evidence)
	}
}

// With root as the only trusted owner, a tree owned by the test user is not
// trusted, unless the test runs as root.
func TestCertExpiryDefaultTrustIsRoot(t *testing.T) {
	b := certTree(t)
	archive := filepath.Join(b, "archive/example/fullchain1.pem")
	if err := os.WriteFile(archive, []byte(pemCert(t, "example.test", t0.Add(days(100)))), 0o644); err != nil {
		t.Fatal(err)
	}
	p := certProbe(t, map[string]any{"paths": []any{filepath.Join(b, "live/example/fullchain.pem")}, "globs": []any{}})
	o := execAt(p, fake.New(nil), osfsFrom(b), t0)
	if os.Getuid() == 0 {
		wantStatus(t, o, result.Pass)
		return
	}
	wantStatus(t, o, result.Error)
	wantSummary(t, o, "owned by uid")
}
