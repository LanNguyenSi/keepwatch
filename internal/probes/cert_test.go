package probes_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func certProbe(t *testing.T, params map[string]any) probes.Probe {
	return prepare(t, "cert_expiry", params)
}

// pemCert returns a self-signed certificate expiring at notAfter.
func pemCert(t *testing.T, cn string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func days(n float64) time.Duration { return time.Duration(n * 24 * float64(time.Hour)) }

const leGlob = "/etc/letsencrypt/live/site/fullchain.pem"

func certFS(files map[string]string) probestest.FakeFS { return probestest.FakeFS{Files: files} }

func execCert(p probes.Probe, files probes.FS) probes.Outcome {
	return execAt(p, fake.New(nil), files, t0)
}

func TestCertExpiryThresholds(t *testing.T) {
	cases := []struct {
		name   string
		left   time.Duration
		params map[string]any
		want   result.Status
		sub    string
	}{
		{"far away", days(200), nil, result.Pass, "valid for at least 30 day(s)"},
		{"exactly warn_days", days(30), nil, result.Pass, ""},
		{"a second below warn_days", days(30) - time.Second, nil, result.Warn, "within 30 day(s)"},
		{"exactly fail_days", days(14), nil, result.Warn, ""},
		{"a second below fail_days", days(14) - time.Second, nil, result.Fail, "within 14 day(s)"},
		{"expires now", 0, nil, result.Fail, ""},
		{"expired yesterday", -days(1), nil, result.Fail, "expired 1 day(s) ago"},
		{"expired long ago", -days(400), nil, result.Fail, "expired 400 day(s) ago"},
		{"custom warn", days(50), map[string]any{"warn_days": 60, "fail_days": 10}, result.Warn, ""},
		{"custom fail", days(50), map[string]any{"warn_days": 60, "fail_days": 55}, result.Fail, ""},
		{"fail_days zero: only expired fails", days(1), map[string]any{"fail_days": 0, "warn_days": 5}, result.Warn, ""},
		{"fail_days zero, expired", -time.Second, map[string]any{"fail_days": 0, "warn_days": 5}, result.Fail, ""},
		{"both zero, valid", time.Hour, map[string]any{"fail_days": 0, "warn_days": 0}, result.Pass, ""},
		{"warn equals fail", days(10), map[string]any{"warn_days": 14, "fail_days": 14}, result.Fail, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fsys := certFS(map[string]string{leGlob: pemCert(t, "site.example.test", t0.Add(c.left))})
			o := execCert(certProbe(t, c.params), fsys)
			wantStatus(t, o, c.want)
			if c.sub != "" && !strings.Contains(allText(o), c.sub) {
				t.Fatalf("%q lacks %q", allText(o), c.sub)
			}
			if c.want == result.Pass {
				if len(o.Evidence) != 0 {
					t.Fatalf("evidence %+v", o.Evidence)
				}
				return
			}
			e := o.Evidence[0]
			if strings.Contains(e.Detail, ", file ") {
				t.Fatalf("the path is the file: %q", e.Detail)
			}
			if e.Subject != leGlob || !strings.Contains(e.Detail, "CN site.example.test") || !strings.Contains(e.Detail, "not after "+t0.Add(c.left).UTC().Format("2006-01-02")) {
				t.Fatalf("evidence %+v", e)
			}
		})
	}
}

func TestCertExpiryCapturedCertificates(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			leaf := fixtureFile(t, v+"/cert_leaf.pem")
			chain := fixtureFile(t, v+"/cert_chain.pem")
			info := fixtureFile(t, v+"/cert_leaf_info.stdout")
			caInfo := fixtureFile(t, v+"/cert_ca_info.stdout")
			notAfter := func(s string) time.Time {
				for _, l := range strings.Split(s, "\n") {
					if d, ok := strings.CutPrefix(l, "notAfter="); ok {
						tm, err := time.Parse("Jan _2 15:04:05 2006 MST", d)
						if err != nil {
							t.Fatal(err)
						}
						return tm
					}
				}
				t.Fatalf("no notAfter in %q", s)
				return time.Time{}
			}
			leafEnd, caEnd := notAfter(info), notAfter(caInfo)
			if !caEnd.After(leafEnd) {
				t.Fatalf("fixture: the CA should outlive the leaf: %v %v", caEnd, leafEnd)
			}
			fsys := certFS(map[string]string{"/srv/leaf.pem": leaf, "/srv/chain.pem": chain})
			p := certProbe(t, map[string]any{"paths": []any{"/srv/leaf.pem", "/srv/chain.pem"}, "globs": []any{}})
			// 20 days before the leaf expires: warn, for both files (the chain's leaf is its first certificate)
			o := execAt(p, fake.New(nil), fsys, leafEnd.Add(-days(20)))
			wantStatus(t, o, result.Warn)
			if !eq(subjects(o), []string{"/srv/chain.pem", "/srv/leaf.pem"}) {
				t.Fatalf("subjects %v", subjects(o))
			}
			if d := o.Evidence[0].Detail; !strings.Contains(d, "CN kw-leaf.example.test") || !strings.Contains(d, "not after "+leafEnd.Format("2006-01-02")) || !strings.Contains(d, "20 day(s) left") && !strings.Contains(d, "19 day(s) left") {
				t.Fatalf("detail %q", d)
			}
			wantStatus(t, execAt(p, fake.New(nil), fsys, leafEnd.Add(-days(5))), result.Fail)
			wantStatus(t, execAt(p, fake.New(nil), fsys, leafEnd.Add(-days(60))), result.Pass)
			wantStatus(t, execAt(p, fake.New(nil), fsys, leafEnd.Add(days(1))), result.Fail)
		})
	}
}

func TestCertExpiryFiles(t *testing.T) {
	good := func(cn string, left time.Duration) string { return pemCert(t, cn, t0.Add(left)) }
	t.Run("paths and globs together, each file once", func(t *testing.T) {
		fsys := certFS(map[string]string{
			"/etc/ssl/a.pem":                        good("a", days(5)),
			"/etc/letsencrypt/live/x/fullchain.pem": good("x", days(5)),
			"/etc/letsencrypt/live/y/fullchain.pem": good("y", days(100)),
			"/etc/letsencrypt/live/y/privkey.pem":   "not read",
		})
		p := certProbe(t, map[string]any{"paths": []any{"/etc/ssl/a.pem", "/etc/letsencrypt/live/x/fullchain.pem"}})
		o := execCert(p, fsys)
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"/etc/letsencrypt/live/x/fullchain.pem", "/etc/ssl/a.pem"}) {
			t.Fatalf("subjects %v", subjects(o))
		}
		wantSummary(t, o, "2 certificate(s)")
	})
	t.Run("globs replaces the default", func(t *testing.T) {
		fsys := certFS(map[string]string{
			"/etc/letsencrypt/live/x/fullchain.pem": good("x", days(1)),
			"/opt/certs/one.pem":                    good("one", days(100)),
		})
		o := execCert(certProbe(t, map[string]any{"globs": []any{"/opt/certs/*.pem"}}), fsys)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "1 certificate(s)")
		o = execCert(certProbe(t, nil), fsys)
		wantStatus(t, o, result.Fail)
	})
	t.Run("a glob that matches nothing is not an error, but with nothing at all the check is skipped", func(t *testing.T) {
		o := execCert(certProbe(t, nil), certFS(nil))
		wantStatus(t, o, result.Skipped)
		wantSummary(t, o, "no certificate file found (0 path(s), 1 pattern(s))")
	})
	t.Run("a listed path that is missing is an error", func(t *testing.T) {
		fsys := certFS(map[string]string{"/opt/b.pem": good("b", days(5))})
		o := execCert(certProbe(t, map[string]any{"paths": []any{"/opt/a.pem", "/opt/b.pem"}, "globs": []any{}}), fsys)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "/opt/a.pem does not exist")
		if !eq(subjects(o), []string{"/opt/b.pem"}) {
			t.Fatalf("a confirmed finding must stay: %v", subjects(o))
		}
	})
	t.Run("a listed path that is missing, alone", func(t *testing.T) {
		wantStatus(t, execCert(certProbe(t, map[string]any{"paths": []any{"/opt/a.pem"}, "globs": []any{}}), certFS(nil)), result.Error)
	})
	t.Run("a file that vanished between the glob and the read is ignored", func(t *testing.T) {
		fsys := certFS(map[string]string{"/opt/a.pem": good("a", days(100))})
		fsys.Errs = map[string]error{"/opt/a.pem": fs.ErrNotExist}
		fsys.Times = map[string]time.Time{"/opt/a.pem": t0}
		o := execCert(certProbe(t, map[string]any{"globs": []any{"/opt/*.pem"}}), fsys)
		wantStatus(t, o, result.Skipped)
	})
	t.Run("files that do not parse", func(t *testing.T) {
		key := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("secret key bytes")}))
		bad := map[string]string{
			"empty":         "",
			"text":          "hello\n",
			"a key":         key,
			"bad DER":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})),
			"truncated PEM": good("a", days(100))[:100],
		}
		for name, content := range bad {
			fsys := certFS(map[string]string{"/opt/ok.pem": good("ok", days(100)), "/opt/bad.pem": content})
			o := execCert(certProbe(t, map[string]any{"paths": []any{"/opt/bad.pem", "/opt/ok.pem"}, "globs": []any{}}), fsys)
			if o.Status != result.Error {
				t.Errorf("%s: status %s (%s)", name, o.Status, o.Summary)
			}
			if strings.Contains(o.Summary, "secret key") || strings.Contains(o.Summary, "hello") {
				t.Errorf("%s: content in the summary: %q", name, o.Summary)
			}
		}
	})
	t.Run("a key block before the certificate is skipped", func(t *testing.T) {
		key := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("k")}))
		fsys := certFS(map[string]string{"/opt/both.pem": key + good("both", days(5))})
		o := execCert(certProbe(t, map[string]any{"paths": []any{"/opt/both.pem"}, "globs": []any{}}), fsys)
		wantStatus(t, o, result.Fail)
	})
	t.Run("the common name is sanitised", func(t *testing.T) {
		fsys := certFS(map[string]string{"/opt/a.pem": good("evil\x1b[31m name\nsecond line", days(5))})
		o := execCert(certProbe(t, map[string]any{"paths": []any{"/opt/a.pem"}, "globs": []any{}}), fsys)
		wantStatus(t, o, result.Fail)
		if strings.ContainsAny(o.Evidence[0].Detail, "\n\x1b") {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
		fsys = certFS(map[string]string{"/opt/a.pem": good("", days(5))})
		o = execCert(certProbe(t, map[string]any{"paths": []any{"/opt/a.pem"}, "globs": []any{}}), fsys)
		if !strings.Contains(o.Evidence[0].Detail, "(no common name)") {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
	})
	t.Run("read problems are errors with the reason", func(t *testing.T) {
		for name, tc := range map[string]struct {
			err  error
			want string
		}{
			"too large": {probes.ErrTooLarge, "larger than 1024 KiB"},
			"unsafe":    {fmt.Errorf("%w: directory /etc/x is writable by group or others (mode 0775)", probes.ErrUnsafe), "writable by group or others"},
			"denied":    {fs.ErrPermission, "permission denied"},
		} {
			fsys := certFS(map[string]string{"/opt/ok.pem": good("ok", days(5))})
			fsys.Errs = map[string]error{"/opt/a.pem": tc.err}
			o := execCert(certProbe(t, map[string]any{"paths": []any{"/opt/a.pem", "/opt/ok.pem"}, "globs": []any{}}), fsys)
			wantStatus(t, o, result.Error)
			if !strings.Contains(o.Summary, tc.want) {
				t.Errorf("%s: %q lacks %q", name, o.Summary, tc.want)
			}
			if !eq(subjects(o), []string{"/opt/ok.pem"}) {
				t.Errorf("%s: subjects %v", name, subjects(o))
			}
		}
	})
	t.Run("a glob that fails, a file system without the operations", func(t *testing.T) {
		wantStatus(t, execCert(certProbe(t, nil), probestest.FakeFS{GlobErr: fmt.Errorf("boom")}), result.Error)
		o := execCert(certProbe(t, nil), probestest.MemFS{})
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "does not offer")
	})
	t.Run("a fail wins over a warn in the summary", func(t *testing.T) {
		fsys := certFS(map[string]string{"/opt/a.pem": good("a", days(5)), "/opt/b.pem": good("b", days(20)), "/opt/c.pem": good("c", days(90))})
		o := execCert(certProbe(t, map[string]any{"globs": []any{"/opt/*.pem"}}), fsys)
		wantStatus(t, o, result.Fail)
		wantSummary(t, o, "1 more within 30 day(s)")
		if !eq(subjects(o), []string{"/opt/a.pem"}) {
			t.Fatalf("a failing result holds failing items only: %v", subjects(o))
		}
	})
	t.Run("a pass names the certificate that expires first", func(t *testing.T) {
		fsys := certFS(map[string]string{"/opt/a.pem": good("a", days(300)), "/opt/b.pem": good("b", days(100)), "/opt/c.pem": good("c", days(200))})
		o := execCert(certProbe(t, map[string]any{"globs": []any{"/opt/*.pem"}}), fsys)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "soonest: /opt/b.pem, 100 day(s) left")
	})
	t.Run("only warnings", func(t *testing.T) {
		fsys := certFS(map[string]string{"/opt/b.pem": good("b", days(20)), "/opt/c.pem": good("c", days(90))})
		o := execCert(certProbe(t, map[string]any{"globs": []any{"/opt/*.pem"}}), fsys)
		wantStatus(t, o, result.Warn)
		wantSummary(t, o, "1 certificate(s) expire within 30 day(s)")
	})
}

func TestCertExpiryManyFiles(t *testing.T) {
	files := map[string]string{}
	one := pemCert(t, "x", t0.Add(days(1)))
	for i := 0; i < 150; i++ {
		files[fmt.Sprintf("/opt/c%03d.pem", i)] = one
	}
	o := execCert(certProbe(t, map[string]any{"globs": []any{"/opt/*.pem"}}), certFS(files))
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 100 || o.Evidence[99].Subject != "(51 more not shown)" {
		t.Fatalf("%d items", len(o.Evidence))
	}
	wantSummary(t, o, "and 51 more")

	thousand := map[string]string{}
	for i := 0; i < 1000; i++ {
		thousand[fmt.Sprintf("/opt/c%04d.pem", i)] = one
	}
	wantStatus(t, execCert(certProbe(t, map[string]any{"globs": []any{"/opt/*.pem"}}), certFS(thousand)), result.Fail)

	many := map[string]string{}
	for i := 0; i < 1001; i++ {
		many[fmt.Sprintf("/opt/c%04d.pem", i)] = one
	}
	o = execCert(certProbe(t, map[string]any{"globs": []any{"/opt/*.pem"}}), certFS(many))
	wantStatus(t, o, result.Error)
	wantSummary(t, o, "only the first 1000 were read")
}

func TestCertExpiryParams(t *testing.T) {
	bad := map[string]map[string]any{
		"relative path":      {"paths": []any{"certs/a.pem"}},
		"unclean path":       {"paths": []any{"/etc/../etc/a.pem"}},
		"trailing slash":     {"paths": []any{"/etc/certs/"}},
		"double slash":       {"paths": []any{"/etc//a.pem"}},
		"control character":  {"paths": []any{"/etc/a\n.pem"}},
		"nul":                {"paths": []any{"/etc/a\x00.pem"}},
		"path too long":      {"paths": []any{"/" + strings.Repeat("a", 5000)}},
		"path not a string":  {"paths": []any{1}},
		"paths not a list":   {"paths": "/etc/a.pem"},
		"relative glob":      {"globs": []any{"live/*/fullchain.pem"}},
		"bad glob":           {"globs": []any{"/etc/[/x"}},
		"glob newline":       {"globs": []any{"/etc/*\n"}},
		"globs not a list":   {"globs": "/etc/*"},
		"warn below fail":    {"warn_days": 5, "fail_days": 10},
		"fail above default": {"fail_days": 31},
		"negative warn":      {"warn_days": -1},
		"too many days":      {"warn_days": 3651},
		"days string":        {"warn_days": "30"},
		"days float":         {"fail_days": 14.5},
		"nothing to check":   {"globs": []any{}},
		"unknown key":        {"endpoints": []any{"example.test:443"}},
	}
	for name, params := range bad {
		t.Run(name, func(t *testing.T) { prepareErr(t, "cert_expiry", params) })
	}
	prepare(t, "cert_expiry", map[string]any{"paths": []string{"/etc/a.pem"}, "globs": []string{}})
	prepare(t, "cert_expiry", map[string]any{"globs": []any{"/etc/ssl/*/[ab].pem", "/x/?"}, "warn_days": 3650, "fail_days": 0})
}

func TestCertExpiryNeverRunsAProgram(t *testing.T) {
	k, _ := probes.Lookup("cert_expiry")
	if len(k.Programs()) != 0 {
		t.Fatalf("programs %v", k.Programs())
	}
	r := fake.New(nil)
	execAt(certProbe(t, nil), r, certFS(map[string]string{leGlob: pemCert(t, "x", t0.Add(days(100)))}), t0)
	if len(r.Calls()) != 0 {
		t.Fatalf("calls %+v", r.Calls())
	}
}
