package probes_test

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// A subject is the key of an evidence item. The probes that name a path, a
// mount point or a free text must not clean or cut it: two subjects that
// differ only in a control character, or only past the length a report shows,
// are two items, and swapping one for the other is a change. The tests in
// this file run each of those probes with two such subjects and follow the
// result through the state (with the real redactor) and the diff.

// subjectCase runs one probe with a name fragment placed where the probe
// takes its subject from.
type subjectCase struct {
	name string
	// kind is the kind of the check, which decides whether a warn alerts.
	kind   string
	status result.Status
	// subject is the subject the probe is expected to produce for frag.
	subject func(frag string) string
	run     func(t *testing.T, frag string) probes.Outcome
}

const (
	longFrag = 300 // runes of padding, more than any probe shows
)

func rawSubjectCases() []subjectCase {
	expiredCert := func(t *testing.T, frag string) probes.Outcome {
		files := map[string]string{"/opt/certs/" + frag + ".pem": pemCert(t, "site.example.test", time.Now().Add(-days(3)))}
		p := certProbe(t, map[string]any{"paths": []any{}, "globs": []any{"/opt/certs/*.pem"}})
		o := execCert(p, certFS(files))
		wantStatus(t, o, result.Fail)
		return o
	}
	fullDisk := func(t *testing.T, frag string) probes.Outcome {
		point := "/mnt/" + frag
		st := &statfsMap{by: map[string]probes.Statfs{point: usage(95, 1)}}
		o := execDisk(diskProbe(t, map[string]any{"fstypes": []any{"ext4"}}), mountFS(mi(7, point, "ext4")), st)
		wantStatus(t, o, result.Fail)
		return o
	}
	dockerTCP := func(t *testing.T, frag string) probes.Outcome {
		b, err := json.Marshal(map[string]any{"hosts": []string{"tcp://" + frag}})
		if err != nil {
			t.Fatal(err)
		}
		none := newRunner().AddResult(dockerPs, inline("", 0))
		o := exec(dockerProbe(t), none, dockerHost(string(b), ""))
		wantStatus(t, o, result.Fail)
		return o
	}
	keysWith := func(t *testing.T, pattern string, homes map[string]string, errs map[string]error) probes.Outcome {
		fsys := probestest.FakeFS{
			Files: map[string]string{"/etc/passwd": "alice:x:1001:1001::/home/alice:/bin/bash\n"},
			Homes: homes,
			Errs:  errs,
		}
		o := execKeys(keysProbe(t), sshdWith("authorizedkeysfile "+pattern, "authorizedkeyscommand none"), fsys, map[string][]string{"alice": {}})
		wantStatus(t, o, result.Warn)
		return o
	}
	return []subjectCase{
		{"cert_expiry file path", "cert_expiry", result.Fail,
			func(f string) string { return "/opt/certs/" + f + ".pem" }, expiredCert},
		{"disk_usage mount point", "disk_usage", result.Fail,
			func(f string) string { return "/mnt/" + f }, fullDisk},
		{"docker_exposure TCP finding", "docker_exposure", result.Fail,
			func(f string) string { return "daemon.json tcp://" + f }, dockerTCP},
		{"authorized_keys pattern warning", "authorized_keys", result.Warn,
			func(f string) string { return "alice:.ssh/" + f + "/%x" },
			func(t *testing.T, f string) probes.Outcome { return keysWith(t, ".ssh/"+f+"/%x", nil, nil) }},
		{"authorized_keys path warning", "authorized_keys", result.Warn,
			func(f string) string { return "alice:.ssh/" + f },
			func(t *testing.T, f string) probes.Outcome {
				return keysWith(t, ".ssh/"+f, nil, map[string]error{"/home/alice\x00.ssh/" + f: probes.ErrTooLarge})
			}},
		{"authorized_keys line warning", "authorized_keys", result.Warn,
			func(f string) string { return "alice:.ssh/" + f + ":1" },
			func(t *testing.T, f string) probes.Outcome {
				return keysWith(t, ".ssh/"+f, map[string]string{"/home/alice\x00.ssh/" + f: "AAAA\n"}, nil)
			}},
	}
}

// checkOf puts an outcome through the state exactly as a run does.
func checkOf(o probes.Outcome, kind string) state.Check {
	r := result.Result{CheckID: "c", Kind: kind, Status: o.Status, Severity: result.High, Summary: o.Summary, Evidence: o.Evidence, Set: o.Set}
	st := state.FromResults([]result.Result{r}, time.Unix(0, 0), redact.Default().Clean)
	return st.Checks[0]
}

func TestSubjectsThatDifferOnlyInWhatIsCleanedStayTwoItems(t *testing.T) {
	pad := strings.Repeat("a", longFrag)
	variants := []struct {
		name string
		a, b string
		// sameDisplay: the state shows both items alike, which is the case
		// where the swap used to be invisible
		sameDisplay bool
	}{
		{"control character", "x\x01", "x\x02", false},
		{"after the display cut", pad + "1", pad + "2", true},
	}
	for _, c := range rawSubjectCases() {
		for _, vr := range variants {
			t.Run(c.name+"/"+vr.name, func(t *testing.T) {
				oa, ob := c.run(t, vr.a), c.run(t, vr.b)
				wantA, wantB := c.subject(vr.a), c.subject(vr.b)
				if got := subjects(oa); !eq(got, []string{wantA}) {
					t.Fatalf("subjects %q, want the raw %q", got, wantA)
				}
				if got := subjects(ob); !eq(got, []string{wantB}) {
					t.Fatalf("subjects %q, want the raw %q", got, wantB)
				}
				if result.SubjectKey(wantA) == result.SubjectKey(wantB) {
					t.Fatal("the test subjects have one key")
				}
				prev, cur := checkOf(oa, c.kind), checkOf(ob, c.kind)
				if len(prev.Items) != 1 || len(cur.Items) != 1 || prev.Items[0].Key == cur.Items[0].Key {
					t.Fatalf("keys %+v / %+v: the two subjects must have two keys", prev.Items, cur.Items)
				}
				if vr.sameDisplay && prev.Items[0].Subject != cur.Items[0].Subject {
					t.Fatalf("the display texts %q and %q were expected to be alike", prev.Items[0].Subject, cur.Items[0].Subject)
				}
				rep := diff.Compute(&state.State{Checks: []state.Check{prev}}, &state.State{Checks: []state.Check{cur}})
				var added, gone []diff.Change
				for _, ch := range rep.Changes {
					switch ch.Kind {
					case diff.SubjectNew:
						added = append(added, ch)
					case diff.SubjectGone:
						gone = append(gone, ch)
					default:
						t.Errorf("unexpected change %+v", ch)
					}
				}
				if len(added) != 1 || len(gone) != 1 {
					t.Fatalf("the swap must be one new and one gone subject: %+v", rep.Changes)
				}
				if !added[0].Alert {
					t.Errorf("the new subject must alert: %+v", added[0])
				}
				if len(rep.Alerts(result.Info)) != 1 {
					t.Errorf("alerts %+v", rep.Alerts(result.Info))
				}
			})
		}
	}
}

// What is shown is still redacted and escaped, and the state holds nothing of
// a secret in a subject: neither where the old cut would have fallen through
// it, nor in the hash.
func TestRawSubjectsAreRedactedAndEscapedForDisplay(t *testing.T) {
	const secret = "hunter2zzz"
	frags := map[string]string{
		"plain":            "dir.password=" + secret,
		"at the old cut":   strings.Repeat("a", 185) + ".password=" + secret,
		"with a control":   "x\x1b[31m.password=" + secret,
		"after a long run": strings.Repeat("b", longFrag) + ".password=" + secret,
	}
	for _, c := range rawSubjectCases() {
		for name, frag := range frags {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				o := c.run(t, frag)
				ck := checkOf(o, c.kind)
				b, err := state.Marshal(&state.State{SchemaVersion: state.SchemaVersion, Checks: []state.Check{ck}})
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(b), secret) {
					t.Fatalf("the state holds the secret:\n%s", b)
				}
				for _, it := range ck.Items {
					if strings.ContainsAny(it.Subject, "\x1b\x01\n") {
						t.Errorf("display subject %q holds a control character", it.Subject)
					}
				}
				if strings.ContainsAny(o.Summary, "\x1b\x01\n") {
					t.Errorf("the summary holds a control character: %q", o.Summary)
				}
				if strings.Contains(name, "plain") || strings.Contains(name, "control") {
					if !strings.Contains(string(b), "[REDACTED]") {
						t.Errorf("the display text was not redacted:\n%s", b)
					}
				}
			})
		}
	}
}

// A partial result names the failing items it confirmed in its summary; the
// subject there is shown, not compared, so it is cleaned.
func TestPartialSummaryShowsACleanedSubject(t *testing.T) {
	files := map[string]string{"/opt/certs/a\x1b[31m\n.pem": pemCert(t, "site.example.test", time.Now().Add(-days(3)))}
	p := certProbe(t, map[string]any{"paths": []any{"/opt/certs/missing.pem"}, "globs": []any{"/opt/certs/*.pem"}})
	o := execCert(p, certFS(files))
	wantStatus(t, o, result.Error)
	wantSummary(t, o, `also found: /opt/certs/a\x1b[31m\n.pem`)
	if !eq(subjects(o), []string{"/opt/certs/a\x1b[31m\n.pem"}) {
		t.Fatalf("subjects %q", subjects(o))
	}
	if strings.ContainsAny(o.Summary, "\x1b\n") {
		t.Fatalf("summary %q", o.Summary)
	}
}

// A summary is redacted by the report after the probe built it, and cut after
// that. A probe that cut a subject first would leave the front of a secret
// that no pattern matches any more. The secret is placed so that every cut
// length a probe used (60 to 300 runes) falls inside it.
func TestSummariesAreRedactedBeforeTheyAreCut(t *testing.T) {
	const (
		tokenSecret = "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" // 36 characters after the prefix
		urlUser     = "user:hunter2yyyyyyyyyyyy"
	)
	if len(tokenSecret) != 40 {
		t.Fatal("test token")
	}
	type role struct {
		name   string
		status result.Status
		// slash: the subject may hold a URL (a "//"), which a clean absolute
		// path cannot
		slash bool
		run   func(t *testing.T, frag string) probes.Outcome
	}
	missingCert := func(t *testing.T, frag string) probes.Outcome {
		p := certProbe(t, map[string]any{"paths": []any{"/opt/certs/" + frag + ".pem"}, "globs": []any{}})
		return execCert(p, certFS(map[string]string{}))
	}
	roles := []role{
		{"cert failing list (subjectList)", result.Fail, false, func(t *testing.T, f string) probes.Outcome {
			return rawSubjectCases()[0].run(t, f)
		}},
		{"cert partial result (partialError)", result.Error, false, func(t *testing.T, f string) probes.Outcome {
			files := map[string]string{"/opt/certs/" + f + ".pem": pemCert(t, "site.example.test", time.Now().Add(-days(3)))}
			p := certProbe(t, map[string]any{"paths": []any{"/opt/certs/missing.pem"}, "globs": []any{"/opt/certs/*.pem"}})
			return execCert(p, certFS(files))
		}},
		{"cert cause of a listed path that does not exist", result.Error, false, missingCert},
		{"cert soonest path of a passing check", result.Pass, false, func(t *testing.T, f string) probes.Outcome {
			files := map[string]string{"/opt/certs/" + f + ".pem": pemCert(t, "site.example.test", time.Now().Add(days(200)))}
			p := certProbe(t, map[string]any{"paths": []any{}, "globs": []any{"/opt/certs/*.pem"}})
			return execCert(p, certFS(files))
		}},
		{"disk failing list (subjectList)", result.Fail, true, func(t *testing.T, f string) probes.Outcome {
			return rawSubjectCases()[1].run(t, f)
		}},
		{"disk cause of a mount that cannot be read", result.Error, true, func(t *testing.T, f string) probes.Outcome {
			point := "/mnt/" + f
			st := &statfsMap{errs: map[string]error{point: errors.New("boom")}}
			return execDisk(diskProbe(t, map[string]any{"fstypes": []any{"ext4"}}), mountFS(mi(7, point, "ext4")), st)
		}},
		{"docker TCP finding (names)", result.Fail, true, func(t *testing.T, f string) probes.Outcome {
			return rawSubjectCases()[2].run(t, f)
		}},
		{"docker cause of a host that is not understood", result.Error, true, func(t *testing.T, f string) probes.Outcome {
			b, err := json.Marshal(map[string]any{"hosts": []string{"ftp://" + f}})
			if err != nil {
				t.Fatal(err)
			}
			none := newRunner().AddResult(dockerPs, inline("", 0))
			return exec(dockerProbe(t), none, dockerHost(string(b), ""))
		}},
		{"authorized_keys warnings (subjectList)", result.Warn, false, func(t *testing.T, f string) probes.Outcome {
			return rawSubjectCases()[4].run(t, f)
		}},
	}
	offsets := []int{20, 45, 65, 85, 105, 125, 160, 190, 265}
	for _, r := range roles {
		for _, off := range offsets {
			forms := map[string]string{"token": strings.Repeat("a", off) + "-" + tokenSecret}
			if r.slash {
				forms["url"] = "ok" + strings.Repeat("a", off) + "/https://" + urlUser + "@host"
				if r.name == "docker TCP finding (names)" || strings.HasPrefix(r.name, "docker cause") {
					// the user info runs from the "//" of the scheme the host has
					forms["url"] = strings.Repeat("a", off) + urlUser + "@host"
				}
			}
			for form, frag := range forms {
				t.Run(r.name+"/"+form+"/"+itoa(off), func(t *testing.T) {
					o := r.run(t, frag)
					if o.Status != r.status {
						t.Fatalf("status %s (%s), want %s", o.Status, o.Summary, r.status)
					}
					secretPart := tokenSecret
					if form == "url" {
						secretPart = urlUser
					}
					if !strings.Contains(o.Summary, secretPart) {
						t.Fatalf("the summary does not hold the whole secret, so a probe cut it: %q", o.Summary)
					}
					shown := redact.Default().Clean(o.Summary)
					for _, leak := range []string{"ZZZZZ", "ghp_Z", "hunter2", "yyyyyy"} {
						if strings.Contains(shown, leak) {
							t.Fatalf("the shown summary holds %q of the secret: %q", leak, shown)
						}
					}
					if !strings.Contains(shown, "[REDACTED]") {
						t.Fatalf("nothing was redacted in %q", shown)
					}
				})
			}
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
