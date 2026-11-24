package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzCleanIdempotent checks the invariant of Clean: its result is a fixed
// point, so a consumer that cleans text an earlier Clean produced (the watch
// daemon cleans the posture state file on the way in) shows exactly what the
// first Clean stored, never more and never less. go test runs the seed
// corpus; CI does not run a fuzzing campaign.
func FuzzCleanIdempotent(f *testing.F) {
	straddle := strings.Repeat("a", MaxFieldRunes-15) + "password=hunter2 tail"
	// Both straddle the cut: the first lands right behind a keyword
	// separator, where the "..." of the cut text could be read as a value;
	// the second cuts a value that the pattern leaves alone (a quote that
	// is never closed) in two.
	behindSeparator := strings.Repeat("a", 1991) + "password=,tail"
	quotedStraddle := strings.Repeat("a", 1985) + `password="ab\cdefghijklmnopqrstuvwxyz` + strings.Repeat("z", 100)
	// A cut that stands inside a multi-byte character would leave bytes the
	// next Escape turns into an escape sequence, so the cut is by runes.
	runeBoundary := strings.Repeat("a", 1999) + strings.Repeat("é", 500)
	seeds := []string{
		"", "plain text", "password=\thunter2", "token:\x00x", "secret=\x01y",
		"--password\x1bz", straddle, behindSeparator, quotedStraddle, runeBoundary,
		"tab\there\r\n", "bad utf8 \xff\xfe",
		"zero\u200bwidth \u202e rtl", `already \x1b escaped [REDACTED]`,
		"\x1b[31mtk_" + strings.Repeat("a", 29) + "\nsecond line",
	}
	for _, p := range positives {
		seeds = append(seeds, p.in)
	}
	seeds = append(seeds, negatives...)
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r := Default()
		once := r.Clean(s)
		if twice := r.Clean(once); twice != once {
			t.Fatalf("Clean is not idempotent on %q:\nonce  %q\ntwice %q", s, once, twice)
		}
		if utf8.RuneCountInString(once) > MaxFieldRunes+3 {
			t.Fatalf("Clean(%q) = %d runes, the limit is %d", s, utf8.RuneCountInString(once), MaxFieldRunes+3)
		}
		if strings.ContainsAny(once, "\x00\n\r\x1b") {
			t.Fatalf("Clean(%q) = %q, an unescaped control character", s, once)
		}
	})
}
