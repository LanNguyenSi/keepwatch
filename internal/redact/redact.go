// Package redact removes secrets from text and makes untrusted text safe to
// print.
//
// Evidence in a keepwatch report comes from host output: process command
// lines, file paths, container names. It can carry a token somebody put in a
// command line, and text a local unprivileged user chose. Every string that
// reaches a terminal, a file, a notification or a log goes through Clean:
//
//  1. Redact replaces secrets with [REDACTED] (built-in patterns, plus the
//     patterns of the configuration's redact.patterns).
//  2. Escape turns every control character into a visible escape sequence.
//
// The order matters: redaction runs on the original text, where a secret is
// still in one piece and a multi-line private key block is still a block;
// escaping runs last, so that the text that is shown can no longer hold a
// character that moves the cursor, starts a terminal escape sequence, forges
// a line or flips the direction of the text.
//
// Redaction is best effort. It catches the common shapes listed in
// docs/running.md; it cannot know a secret that has no recognisable shape. Probes
// keep secrets out of evidence in the first place (they never print file
// contents, only fingerprints and counts); this package is the second line.
package redact

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
)

// Replacement is what a redacted secret is replaced with.
const Replacement = "[REDACTED]"

// Bounds for the patterns an operator adds in the configuration.
const (
	// MaxPatterns is the largest number of extra patterns.
	MaxPatterns = 32
	// MaxPatternLen is the longest extra pattern, in bytes.
	MaxPatternLen = 256
	// MaxProgramSize is the largest compiled program, in instructions, of an
	// extra pattern. Matching is linear in the text, but a repeat such as
	// (a|b|c|d|e){1000} compiles to thousands of instructions, and every
	// instruction costs time on every byte of every field that is shown. Real
	// patterns need a few dozen.
	MaxProgramSize = 1000
)

// MaxFieldRunes bounds the text Clean returns for one field. A longer field
// is cut and ends in "...". It keeps a hostile or accidental megabyte out of
// reports and notifications.
const MaxFieldRunes = 2000

// ValidatePattern reports why p cannot be used as an extra redaction pattern:
// empty, too long, not valid RE2 syntax, compiling to a program of more than
// MaxProgramSize instructions, or able to match the empty string (which would
// "redact" every position of every text).
func ValidatePattern(p string) error {
	if p == "" {
		return errors.New("must not be empty")
	}
	if len(p) > MaxPatternLen {
		return fmt.Errorf("is %d bytes long, the limit is %d", len(p), MaxPatternLen)
	}
	// The same steps regexp.Compile takes, to see the size of the program.
	parsed, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return fmt.Errorf("is not a valid regular expression: %v", err)
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return fmt.Errorf("is not a valid regular expression: %v", err)
	}
	if n := len(prog.Inst); n > MaxProgramSize {
		return fmt.Errorf("is too complex: it compiles to %d instructions, the limit is %d", n, MaxProgramSize)
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return fmt.Errorf("is not a valid regular expression: %v", err)
	}
	if re.MatchString("") {
		return errors.New("matches the empty string")
	}
	return nil
}

// A rule replaces matches of re with repl (a regexp.Expand template).
type rule struct {
	re   *regexp.Regexp
	repl string
}

// A value after "name=" or "name:": a quoted string (backslash escapes
// count; a quote that is never closed runs to the end of the text, so a
// secret is not left because its closing quote is missing), the replacement
// itself (so redacting twice changes nothing), or a run of characters up to
// a separator. A NUL byte, which separates the arguments of a command line,
// ends a value as a space does.
const valueRe = `"(?:[^"\\]|(?s:\\.))*(?:"|\\?$)|'(?:[^'\\]|(?s:\\.))*(?:'|\\?$)|\[REDACTED\]|[^\s\x00"',;&][^\s\x00",;&]*`

// tokenStart is what must stand in front of a token or a keyword whose prefix
// is short or common enough to occur inside a longer word or a blob of encoded
// text: a word boundary (zero width, so a character that an earlier match
// ended on is still available to the next one), or a terminal CSI sequence.
// "\x1b[31m" leaves an "m" in front of the token, a letter that a word
// boundary counts as part of a word. The CSI is matched, not asserted (RE2 has
// no lookbehind): it is the first group, and the replacement puts it back
// (the group is empty when the boundary matched). The prefixes of GitHub,
// GitLab and Slack tokens are long and specific, so those patterns take a
// token after any character: "aghp_...", "7ghp_..." and "_ghp_..." are
// tokens too.
const tokenStart = `(?:\b|(` + csi + `))`

// csi is a CSI sequence of a terminal (a color change, a cursor move): ESC [,
// parameter bytes, intermediate bytes and a final byte. Other kinds of escape
// sequence (ESC ( B, ESC c, the 8-bit CSI, a CSI that never ends) are not
// recognised.
const csi = `\x1b\[[0-?]*[ -/]*[@-~]`

// builtin lists the built-in patterns, specific shapes first. All use RE2
// (linear time), none can backtrack.
var builtin = []rule{
	// PEM private key blocks, also a block cut off before its end line.
	{regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)`), "[REDACTED private key]"},
	// scheme://user:password@host and scheme://token@host. The user info
	// runs to the last @ before the first /, ? or # (a password can hold an
	// @). No word boundary in front of the scheme: a scheme glued to the
	// text before it ("1https://", "_ssh://") is still the scheme of the URL.
	// The first alternative takes host text that comes between the scheme and
	// the user info and ends in a space or a tab, or in a comma and then a
	// space or a tab ("tcp://host, user:password@host"), when the user info
	// has the form user:password; it comes first, so that a second
	// credential behind the first one ("tcp://u:p@h1, bob:pw@h2") is covered
	// too. A token alone behind such text ("tcp://host, token@host") is not,
	// because it cannot be told from an address in a list of hosts. The
	// second alternative is the user info right behind the scheme.
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)(?:[^\s\x00/?#]*[ \t][ \t]*[^\s\x00/?#]*:[^\s\x00/?#]*@|[^\s\x00/?#]+@)`), "${1}" + Replacement + "@"},
	// Authorization: Bearer abc, Authorization=Basic abc, "authorization": "..."
	{regexp.MustCompile(`(?i)` + tokenStart + `(authorization["']?[\s\x00]*[:=][\s\x00]*)(?:"[^"]*"|'[^']*'|(?:(?:bearer|basic|digest|token)\s+)?[^\s\x00"',;]+)`), "${1}${2}" + Replacement},
	// Cookie and Set-Cookie: the rest of the line
	{regexp.MustCompile(`(?i)` + tokenStart + `((?:set-)?cookie2?["']?[ \t\x00]*[:=][ \t\x00]*)[^\r\n\x00]+`), "${1}${2}" + Replacement},
	// a bare bearer token
	{regexp.MustCompile(`(?i)` + tokenStart + `(bearer\s+)[A-Za-z0-9._~+/=-]{16,}`), "${1}${2}" + Replacement},
	// name=value and name: value, also in JSON ("name": "value"), when the
	// name ends in a secret word (the word must be followed directly by the
	// separator): "token_file" and "passwordauthentication" do not qualify
	// and are left alone.
	{regexp.MustCompile(`(?i)((?:password|passwd|passphrase|secret|(?:secret|auth|signing|encryption|master)[_-]?key|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)["']?\s*[=:]\s*)(` + valueRe + `)`), "${1}" + Replacement},
	// pass and pwd as a name of their own or as the last word of one
	// (DB_PASS=..., MYSQL_PWD=..., pwd: ...), not as the end of a longer word
	// ("bypass=1")
	{regexp.MustCompile(`(?i)((?:^|[^a-z0-9]|` + csi + `)(?:pass|pwd)["']?\s*[=:]\s*)(` + valueRe + `)`), "${1}" + Replacement},
	// env-style NAME_KEY=value
	{regexp.MustCompile(`(?i)((?:^|[^a-z0-9])[a-z0-9]+[_-]key["']?\s*=\s*)(` + valueRe + `)`), "${1}" + Replacement},
	// --password hunter2, -token abc (a value that does not start with "-");
	// a NUL byte between flag and value counts as a space, a quote around the
	// flag ("--token" x) is allowed. A flag starts at the beginning of the text
	// or after any character that cannot be part of a word (space, NUL, quote,
	// "=", "(", "[", ",", ...): inside a word such as "prohibit-password" or
	// "without-password" the "-password" is no flag and the next word is no
	// value. Only a letter, digit, "_" or "-" in front keeps a match from
	// starting, so a real flag behind any other separator stays redacted.
	{regexp.MustCompile(`(?i)(^|[^a-z0-9_-]|` + csi + `)(-[a-z0-9-]*(?:password|passwd|passphrase|secret|token|api-?key)["']?[\s\x00]+)[^\s\x00-][^\s\x00]*`), "${1}${2}" + Replacement},
	// AWS access key ids
	{regexp.MustCompile(tokenStart + `(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b`), "${1}" + Replacement},
	// GitHub tokens
	{regexp.MustCompile(`(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`), Replacement},
	// GitLab personal access tokens
	{regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), Replacement},
	// API keys of the sk- family (OpenAI, Anthropic: sk-..., sk-proj-..., sk-ant-...)
	{regexp.MustCompile(tokenStart + `sk-[A-Za-z0-9_-]{20,}`), "${1}" + Replacement},
	// ntfy access tokens
	{regexp.MustCompile(tokenStart + `tk_[A-Za-z0-9]{29,}\b`), "${1}" + Replacement},
	// Slack tokens
	{regexp.MustCompile(`xox[abeprs]-[A-Za-z0-9-]{10,}`), Replacement},
	// Google API keys
	{regexp.MustCompile(tokenStart + `AIza[0-9A-Za-z_-]{35}`), "${1}" + Replacement},
	// Stripe keys
	{regexp.MustCompile(tokenStart + `[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b`), "${1}" + Replacement},
	// JSON web tokens
	{regexp.MustCompile(tokenStart + `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "${1}" + Replacement},
}

// Redactor removes secrets from text. The zero value is not usable; use New
// or Default. A Redactor is immutable and safe for concurrent use.
type Redactor struct {
	extra []*regexp.Regexp
}

var defaultRedactor = &Redactor{}

// Default returns a Redactor with the built-in patterns only.
func Default() *Redactor { return defaultRedactor }

// New returns a Redactor with the built-in patterns and the given extra
// patterns. Each extra pattern must pass ValidatePattern, and there may be at
// most MaxPatterns of them. An extra pattern with a capturing group redacts
// only the text of its first group; without one it redacts the whole match.
func New(extra []string) (*Redactor, error) {
	if len(extra) > MaxPatterns {
		return nil, fmt.Errorf("%d redaction patterns, the limit is %d", len(extra), MaxPatterns)
	}
	r := &Redactor{}
	for i, p := range extra {
		if err := ValidatePattern(p); err != nil {
			return nil, fmt.Errorf("redaction pattern %d %v", i+1, err)
		}
		r.extra = append(r.extra, regexp.MustCompile(p))
	}
	return r, nil
}

// Redact replaces secrets in s with [REDACTED]. It leaves every other
// character alone, control characters included: use Clean for text that is
// going to be shown.
func (r *Redactor) Redact(s string) string {
	for _, b := range builtin {
		s = b.re.ReplaceAllString(s, b.repl)
	}
	for _, re := range r.extra {
		s = replaceExtra(re, s)
	}
	return s
}

// replaceExtra replaces the first capturing group of each match of re, or the
// whole match when re has no group (or the group did not take part). An empty
// match is left alone.
func replaceExtra(re *regexp.Regexp, s string) string {
	var sb strings.Builder
	last := 0
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		start, end := m[0], m[1]
		if len(m) >= 4 && m[2] >= 0 {
			start, end = m[2], m[3]
		}
		if end <= start {
			continue
		}
		sb.WriteString(s[last:start])
		sb.WriteString(Replacement)
		last = end
	}
	sb.WriteString(s[last:])
	return sb.String()
}

// Clean returns s as text that is safe to show: secrets redacted, control
// characters escaped (see Escape), and cut to MaxFieldRunes. The result is a
// single line of valid UTF-8. A nil Redactor uses the built-in patterns.
func (r *Redactor) Clean(s string) string {
	if r == nil {
		r = defaultRedactor
	}
	return truncate(Escape(r.Redact(s)), MaxFieldRunes)
}

func truncate(s string, runes int) string {
	n := 0
	for i := range s {
		if n == runes {
			return s[:i] + "..."
		}
		n++
	}
	return s
}
