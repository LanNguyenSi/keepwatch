package probes

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

const (
	maxCertFile      = 1 << 20
	defaultCertGlob  = "/etc/letsencrypt/live/*/fullchain.pem"
	maxCertCandidate = 1000
)

// certExpiry checks when the certificates in files expire. Files only: it
// never connects anywhere.
//
// Parameters:
//
//	paths      (list of absolute file paths, default none)  certificate files
//	globs      (list of absolute filepath.Glob patterns, default
//	           /etc/letsencrypt/live/*/fullchain.pem)  more certificate files
//	warn_days  (integer 0 to 3650, default 30)  remaining validity below which
//	           the status is warn
//	fail_days  (integer 0 to 3650, default 14)  remaining validity below which
//	           the status is fail (an expired certificate always is); must not
//	           exceed warn_days
//
// List semantics: "paths" and "globs" under checks.<id>.params REPLACE their
// defaults (set "globs: []" to drop the Let's Encrypt pattern; the two lists
// must not both end up empty). They are separate lists: giving "paths" does not
// remove the default glob. Lists from conf.d drop-ins are already appended to
// the main file's list when the config is loaded.
//
// Every candidate file is read with ReadTrusted: symbolic links are followed
// (certbot keeps the current certificate in live/ as a link into archive/), but
// only when every directory the path goes through (the ones that hold a link
// as well as the ones it leads into), every link and the resolved file are
// owned by root and not writable by group or others; otherwise that file is
// error with the reason. A link in a directory that a user can write to is
// refused although the certificate it names is root's: its owner could repoint
// it at any other root-owned certificate. This holds for plain files in other places as well: a certificate in
// a directory a user can write to would let that user decide the date. A file
// larger than 1 MiB, not a regular file, or one that does not parse is error
// for that file, and the status is error with the confirmed findings of the
// other files kept. A listed path that does not exist is error too; a glob that
// matches nothing is not. If no file is found at all the check is skipped.
// A glob that matches something that is not a certificate file (a directory)
// makes that match an error, so patterns should name certificate files.
//
// The first CERTIFICATE block of a file is examined (for a chain such as
// fullchain.pem that is the leaf). Remaining validity is NotAfter minus now:
// below fail_days days is a fail, below warn_days a warn, subject = the path as
// listed or matched, detail = subject common name, the NotAfter date and the
// days left. With a fail the warnings are counted in the summary and carried in
// Outcome.Warnings (an exception for every failing certificate leaves a warn). At most
// 1000 candidate files are read.
type certExpiry struct{}

func (certExpiry) Name() string       { return "cert_expiry" }
func (certExpiry) Programs() []string { return nil }

func (certExpiry) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	absPath := func(s string) error {
		if !strings.HasPrefix(s, "/") || filepath.Clean(s) != s || strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) || len(s) > 4096 {
			return fmt.Errorf("%q is not a clean absolute path", clean(s, 80))
		}
		return nil
	}
	globPat := func(s string) error {
		if !strings.HasPrefix(s, "/") || strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) || len(s) > 4096 {
			return fmt.Errorf("%q is not an absolute pattern", clean(s, 80))
		}
		if _, err := filepath.Match(s, ""); err != nil {
			return fmt.Errorf("%q is not a valid pattern: %v", clean(s, 80), err)
		}
		return nil
	}
	paths := p.strList("paths", false, false, nil, absPath)
	globs := p.strList("globs", false, false, []string{defaultCertGlob}, globPat)
	warn := p.integer("warn_days", 30, 0, 3650)
	fail := p.integer("fail_days", 14, 0, 3650)
	if err := p.err(); err != nil {
		return nil, err
	}
	if fail > warn {
		return nil, fmt.Errorf("fail_days (%d) must not be higher than warn_days (%d)", fail, warn)
	}
	if len(paths) == 0 && len(globs) == 0 {
		return nil, errors.New("paths and globs are both empty, there is nothing to check")
	}
	return certProbe{paths: paths, globs: globs, warn: time.Duration(warn) * 24 * time.Hour, fail: time.Duration(fail) * 24 * time.Hour}, nil
}

type certProbe struct {
	paths, globs []string
	warn, fail   time.Duration
}

func (c certProbe) Run(ctx context.Context, env *Env) Outcome {
	listed := map[string]bool{}
	cand := map[string]bool{}
	for _, p := range c.paths {
		listed[p] = true
		cand[p] = true
	}
	for _, g := range c.globs {
		matches, err := env.glob(g)
		if err != nil {
			return *errorOutcome("glob %s: %s", show(g), show(err.Error()))
		}
		for _, m := range matches {
			cand[m] = true
		}
	}
	if len(cand) == 0 {
		return Outcome{Status: result.Skipped, Summary: fmt.Sprintf("no certificate file found (%d path(s), %d pattern(s)), check skipped", len(c.paths), len(c.globs))}
	}
	files := make([]string, 0, len(cand))
	for f := range cand {
		files = append(files, f)
	}
	sort.Strings(files)
	var causes []string
	if len(files) > maxCertCandidate {
		causes = append(causes, fmt.Sprintf("%d certificate files found, only the first %d were read", len(files), maxCertCandidate))
		files = files[:maxCertCandidate]
	}

	now := env.now()
	var fails, warns []result.Evidence
	var soonest time.Duration
	soonestPath := ""
	read := 0
	for _, f := range files {
		data, resolved, err := env.readTrusted(f, maxCertFile)
		if err != nil {
			switch {
			case errors.Is(err, errNoCapability):
				return *errorOutcome("%v", err)
			case errors.Is(err, fs.ErrNotExist) && !listed[f]:
				continue // vanished between the glob and the read
			case errors.Is(err, fs.ErrNotExist):
				causes = append(causes, fmt.Sprintf("%s does not exist", show(f)))
			case errors.Is(err, ErrTooLarge):
				causes = append(causes, fmt.Sprintf("%s is larger than %d KiB", show(f), maxCertFile>>10))
			default:
				causes = append(causes, fmt.Sprintf("%s: %s", show(f), show(err.Error())))
			}
			continue
		}
		cert, err := firstCertificate(data)
		if err != nil {
			causes = append(causes, fmt.Sprintf("%s: %v", show(f), err))
			continue
		}
		read++
		left := cert.NotAfter.Sub(now)
		if soonestPath == "" || left < soonest {
			soonest, soonestPath = left, f
		}
		if left >= c.warn {
			continue
		}
		cn := clean(cert.Subject.CommonName, 80)
		if cn == "" {
			cn = "(no common name)"
		}
		// The subject is the path as it is: it is the key of the item, so it is
		// neither cleaned nor cut here (the report does that for display).
		ev := result.Evidence{
			Subject: f,
			Detail:  fmt.Sprintf("CN %s, not after %s, %s%s", cn, cert.NotAfter.UTC().Format("2006-01-02"), daysLeft(left), resolvedNote(f, resolved)),
		}
		if left < c.fail {
			fails = append(fails, ev)
		} else {
			warns = append(warns, ev)
		}
	}
	if len(causes) > 0 {
		if len(causes) > maxPartialSubjects {
			causes = append(causes[:maxPartialSubjects], fmt.Sprintf("and %d more problems", len(causes)-maxPartialSubjects))
		}
		shown, _, set := limitEvidence(fails)
		o := partialError(causes, fails)
		o.Evidence, o.Set = shown, set
		return o
	}
	if read == 0 {
		return Outcome{Status: result.Skipped, Summary: "no certificate file found, check skipped"}
	}
	switch {
	case len(fails) > 0:
		shown, hidden, set := limitEvidence(fails)
		s := fmt.Sprintf("%d certificate(s) expire within %s or are expired: %s", len(fails), daysText(c.fail), subjectList(shown, 5))
		if len(warns) > 0 {
			s += fmt.Sprintf("; %d more within %s", len(warns), daysText(c.warn))
		}
		shownWarns, _, warnSet := limitEvidence(warns)
		return Outcome{Status: result.Fail, Summary: s + moreNote(hidden), Evidence: shown, Set: set, Warnings: shownWarns, WarningsSet: warnSet}
	case len(warns) > 0:
		shown, hidden, set := limitEvidence(warns)
		return Outcome{
			Status:   result.Warn,
			Summary:  fmt.Sprintf("%d certificate(s) expire within %s: %s", len(warns), daysText(c.warn), subjectList(shown, 5)) + moreNote(hidden),
			Evidence: shown,
			Set:      set,
		}
	}
	return Outcome{Status: result.Pass, Summary: fmt.Sprintf("%d certificate(s) valid for at least %s; soonest: %s, %s", read, daysText(c.warn), show(soonestPath), daysLeft(soonest))}
}

func resolvedNote(path, resolved string) string {
	if resolved == "" || resolved == path {
		return ""
	}
	return ", file " + show(resolved)
}

func daysText(d time.Duration) string { return fmt.Sprintf("%d day(s)", int(d/(24*time.Hour))) }

// daysLeft renders the remaining validity; negative means expired.
func daysLeft(left time.Duration) string {
	if left < 0 {
		return fmt.Sprintf("expired %d day(s) ago", int((-left)/(24*time.Hour)))
	}
	return fmt.Sprintf("%d day(s) left", int(left/(24*time.Hour)))
}

// firstCertificate parses the first CERTIFICATE block of a PEM file. The error
// text never quotes the file.
func firstCertificate(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no PEM certificate found")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("the certificate does not parse")
		}
		return cert, nil
	}
}
