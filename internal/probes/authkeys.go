package probes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Limits of authorizedKeys.
const (
	passwdFile         = "/etc/passwd"
	maxPasswd          = 4 << 20
	maxKeyFile         = 256 << 10
	maxKeyLine         = 16 << 10
	maxKeyBlob         = 16 << 10
	defaultKeyFileList = ".ssh/authorized_keys .ssh/authorized_keys2"
)

// authorizedKeys compares the public keys in the users' authorized keys files
// with the keys the configuration expects (authorized_keys.expected: user name
// to a list of "SHA256:<base64>" fingerprints, as "ssh-keygen -l" prints them).
//
// It takes no parameters (and so has no list parameters). The expected keys
// are the top-level authorized_keys.expected section, whose lists from conf.d
// drop-ins are appended to the main file's. Without any expected entry the
// check is skipped: there is nothing to compare with, and treating every key as
// unexpected would make the first run a wall of failures.
//
// Which users: every account in /etc/passwd with uid 0 or uid 1000 and above
// and a login shell (a shell whose file name is neither nologin nor false;
// an empty shell field means /bin/sh), plus every user named in the expected
// section. Which files: the value of AuthorizedKeysFile in "sshd -T" (that run
// is shared with sshd_effective), or ".ssh/authorized_keys
// .ssh/authorized_keys2" when sshd -T cannot be used; "none" means no file. The
// tokens %h (home), %u (user name), %U (uid) and %% are expanded; any other
// token makes that pattern unusable and is reported. A relative path is
// relative to the home. If sshd -T fails, the default paths are read, the
// findings are kept, and the status is error: the real list of files and an
// AuthorizedKeysCommand are unknown. The same holds when the output lacks
// authorizedkeysfile or authorizedkeyscommand or has either twice, because
// sshd -T prints every option and such output is not sshd -T output. sshd -T runs without a connection
// specification, so Match blocks are not evaluated and can change the files
// for some users.
//
// Reading the files. The user owns every file and directory below the home and
// can replace any of them with a link at any time, and keepwatch runs as root,
// so a path inside the home is read through the kernel's confinement to the
// home (ReadHomeFile): a link that leaves the home, an absolute link, ".."
// out of it, a file that is not a regular file, a file owned by somebody
// other than the user or root, a file larger than 256 KiB are all refused and
// reported as a warning with the reason, never read. A FIFO is not opened
// blocking and not read; a device node, which only root can create, is never
// opened. An absolute path outside the home (a root-managed directory such as
// /etc/ssh/keys/%u) is read like a certificate: links are followed only when
// the resolved file and every directory above it are root-owned and not
// writable by others (ReadTrusted). Nothing of a file's content is put into a
// result except the type, the fingerprint and the line number of a key; a
// line that is not a key is only counted and its line number named, so a
// file that is not an authorized keys file (a link to a file of another
// user, say) leaks nothing.
//
// A line is [options] type base64-key [comment]. The options (which may
// contain quoted spaces) are skipped, the type must be one of ssh-ed25519,
// ssh-rsa, ssh-dss, ecdsa-sha2-nistp256/384/521 and the two sk- types, and the
// base64 blob must decode and start with the same type name. A certificate
// (a -cert-v01 type) is not a key to compare and counts as a line that is not a
// key. The fingerprint is the unpadded base64 of the SHA-256 of the
// blob, computed here. A line that is not blank, not a comment and not a key
// is a warning.
//
// Result: a key in a file that the user's expected list does not have is a
// fail (subject "<user>:SHA256:..."), also for a user without any expected
// entry. Without a fail, an expected key that no file has (same subject form),
// a file that was refused or has unparseable lines (subject
// "<user>:<path>" or "<user>:<path>:<line>"), a passwd line that does not
// parse, an expected user without an account, and an AuthorizedKeysCommand
// other than none (subject "authorizedkeyscommand", its keys cannot be
// checked) make the status warn. When there is a fail, the warnings are
// counted in the summary and not listed, because every evidence item of a
// failing result is a failing item. A user who makes their own file
// unreadable or unusable gets a warning, never a pass.
type authorizedKeys struct{}

func (authorizedKeys) Name() string       { return "authorized_keys" }
func (authorizedKeys) Programs() []string { return []string{"sshd"} }

func (authorizedKeys) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	if err := p.err(); err != nil {
		return nil, err
	}
	return keysProbe{}, nil
}

type keysProbe struct{}

// account is a user whose keys are examined.
type account struct {
	name string
	uid  uint32
	home string
	has  bool // there is a passwd entry
}

func (keysProbe) Run(ctx context.Context, env *Env) Outcome {
	var causes []string
	files := strings.Fields(defaultKeyFileList)
	var cmdWarn []result.Evidence
	res, out := run(ctx, env, []string{"sshd", "-T"}, 0)
	if out != nil && out.Status == result.Skipped {
		return *out
	}
	expected := map[string]map[string]bool{}
	for user, fps := range env.AuthorizedKeys {
		set := map[string]bool{}
		for _, fp := range fps {
			set[strings.TrimRight(fp, "=")] = true
		}
		expected[user] = set
	}
	if len(expected) == 0 {
		return Outcome{Status: result.Skipped, Summary: "authorized_keys.expected is not configured, there is nothing to compare the keys with (ssh-keygen -lf <file> prints the fingerprints)"}
	}
	switch {
	case out != nil:
		causes = append(causes, out.Summary)
	case res.ExitCode != 0:
		causes = append(causes, unexpectedExit("sshd -T", res).Summary)
	default:
		cfg, err := parseSSHDRaw(string(res.Stdout))
		if err != nil {
			causes = append(causes, fmt.Sprintf("sshd -T: %v", err))
			break
		}
		// sshd -T prints every option, so a missing or repeated one means the
		// output is not what it looks like.
		fileVals, cmdVals := cfg["authorizedkeysfile"], cfg["authorizedkeyscommand"]
		if len(fileVals) != 1 || len(cmdVals) != 1 {
			causes = append(causes, "sshd -T did not print authorizedkeysfile and authorizedkeyscommand exactly once each")
			break
		}
		files = strings.Fields(fileVals[0])
		if len(files) == 1 && files[0] == "none" {
			files = nil
		}
		if strings.TrimSpace(cmdVals[0]) != "none" {
			cmdWarn = append(cmdWarn, result.Evidence{
				Subject: "authorizedkeyscommand",
				Detail:  "AuthorizedKeysCommand is set (" + clean(cmdVals[0], 80) + "); the keys it supplies cannot be checked",
			})
		}
	}
	if len(causes) > 0 {
		causes[0] = "cannot tell which key files sshd reads, the default paths were used: " + causes[0]
	}

	accounts, warns, err := keyAccounts(env, expected)
	if err != nil {
		return *errorOutcome("%v", err)
	}
	warns = append(warns, cmdWarn...)

	var fails []result.Evidence
	total := 0
	for _, a := range accounts {
		if !a.has {
			continue
		}
		found := map[string]string{} // fingerprint -> detail
		for _, pattern := range files {
			rel, abs, perr := expandKeyPath(pattern, a)
			if perr != nil {
				warns = append(warns, result.Evidence{Subject: a.name + ":" + clean(pattern, 60), Detail: perr.Error()})
				continue
			}
			shown := rel
			var data []byte
			var rerr error
			if abs != "" {
				shown = abs
				data, _, rerr = env.readTrusted(abs, maxKeyFile)
			} else {
				data, rerr = env.readHome(a.home, a.uid, rel, maxKeyFile)
			}
			if rerr != nil {
				if errors.Is(rerr, fs.ErrNotExist) {
					continue
				}
				if errors.Is(rerr, errNoCapability) {
					return *errorOutcome("%v", rerr)
				}
				warns = append(warns, result.Evidence{Subject: a.name + ":" + clean(shown, 80), Detail: "not read: " + keyReadReason(rerr)})
				continue
			}
			keys, bad := parseAuthorizedKeys(string(data))
			for _, line := range bad {
				warns = append(warns, result.Evidence{
					Subject: fmt.Sprintf("%s:%s:%d", a.name, clean(shown, 80), line.n),
					Detail:  "line is not a public key: " + line.why,
				})
			}
			for _, k := range keys {
				if _, dup := found[k.fp]; !dup {
					found[k.fp] = fmt.Sprintf("%s key in %s line %d", k.typ, clean(shown, 80), k.line)
				}
			}
		}
		total += len(found)
		for fp, detail := range found {
			if !expected[a.name][fp] {
				fails = append(fails, result.Evidence{Subject: a.name + ":" + fp, Detail: detail})
			}
		}
		for fp := range expected[a.name] {
			if _, ok := found[fp]; !ok {
				warns = append(warns, result.Evidence{Subject: a.name + ":" + fp, Detail: "expected key not found in any authorized keys file"})
			}
		}
	}

	switch {
	case len(causes) > 0:
		shown, _ := limitEvidence(fails)
		o := partialError(causes, fails)
		o.Evidence = shown
		return o
	case len(fails) > 0:
		shown, hidden := limitEvidence(fails)
		s := fmt.Sprintf("%d unexpected authorized key(s): %s", len(fails), subjectList(shown, 5))
		if len(warns) > 0 {
			s += fmt.Sprintf("; also %d warning(s): %s", len(warns), subjectList(sortedEvidence(warns), 5))
		}
		return Outcome{Status: result.Fail, Summary: s + moreNote(hidden), Evidence: shown}
	case len(warns) > 0:
		shown, hidden := limitEvidence(warns)
		return Outcome{
			Status:   result.Warn,
			Summary:  fmt.Sprintf("no unexpected authorized keys, but %d thing(s) need a look: %s", len(warns), subjectList(shown, 5)) + moreNote(hidden),
			Evidence: shown,
		}
	}
	return Outcome{Status: result.Pass, Summary: fmt.Sprintf("all %d authorized key(s) of %d user(s) are expected", total, len(accounts))}
}

func sortedEvidence(ev []result.Evidence) []result.Evidence {
	out := append([]result.Evidence(nil), ev...)
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}

func subjectList(ev []result.Evidence, n int) string {
	var s []string
	for i, e := range ev {
		if i == n {
			s = append(s, "...")
			break
		}
		s = append(s, e.Subject)
	}
	return strings.Join(s, ", ")
}

// keyReadReason renders why a key file was refused, without the content.
func keyReadReason(err error) string {
	switch {
	case errors.Is(err, ErrTooLarge):
		return fmt.Sprintf("larger than %d KiB", maxKeyFile>>10)
	case strings.Contains(err.Error(), "escapes"):
		return "a symbolic link or path leads out of the home directory"
	}
	return clean(err.Error(), 300)
}

var userNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\$?$`)

// keyAccounts lists the users to examine, sorted by name: the login accounts
// of /etc/passwd and the users of the expected section. Problems with single
// lines become warnings.
func keyAccounts(env *Env, expected map[string]map[string]bool) ([]account, []result.Evidence, error) {
	b, err := env.FS.ReadFile(passwdFile, maxPasswd)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read %s: %s", passwdFile, clean(err.Error(), 120))
	}
	var warns []result.Evidence
	byName := map[string]account{}
	for i, line := range strings.Split(string(b), "\n") {
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		f := strings.Split(line, ":")
		uid, uerr := strconv.ParseUint(safeIndex(f, 2), 10, 32)
		if len(f) != 7 || !userNameRe.MatchString(f[0]) || uerr != nil || !strings.HasPrefix(f[5], "/") {
			warns = append(warns, result.Evidence{Subject: fmt.Sprintf("passwd:%d", i+1), Detail: "line of /etc/passwd could not be read, its user was not examined"})
			continue
		}
		name := f[0]
		login := loginShell(f[6])
		_, named := expected[name]
		if !(named || (login && (uid == 0 || uid >= 1000))) {
			continue
		}
		if _, dup := byName[name]; dup {
			continue
		}
		byName[name] = account{name: name, uid: uint32(uid), home: path.Clean(f[5]), has: true}
	}
	for name := range expected {
		if _, ok := byName[name]; !ok {
			byName[name] = account{name: name}
			warns = append(warns, result.Evidence{Subject: name, Detail: "named in authorized_keys.expected but has no usable account in /etc/passwd"})
		}
	}
	out := make([]account, 0, len(byName))
	for _, a := range byName {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, warns, nil
}

func safeIndex(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}

// loginShell reports whether a shell field allows a login: anything but a
// shell named nologin or false.
func loginShell(shell string) bool {
	switch path.Base(shell) {
	case "nologin", "false":
		return false
	}
	return true
}

// expandKeyPath expands the tokens of one AuthorizedKeysFile entry for an
// account. It returns either a path relative to the home (rel) or an absolute
// path outside it (abs). An absolute path inside the home is turned into a
// relative one so that it is read with the home's confinement.
func expandKeyPath(pattern string, a account) (rel, abs string, err error) {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '%' {
			b.WriteByte(pattern[i])
			continue
		}
		i++
		if i == len(pattern) {
			return "", "", errors.New("pattern ends in a lone %")
		}
		switch pattern[i] {
		case '%':
			b.WriteByte('%')
		case 'h':
			b.WriteString(a.home)
		case 'u':
			b.WriteString(a.name)
		case 'U':
			b.WriteString(strconv.FormatUint(uint64(a.uid), 10))
		default:
			return "", "", fmt.Errorf("pattern uses the token %%%s, which keepwatch does not expand", clean(string(pattern[i]), 4))
		}
	}
	p := b.String()
	if strings.ContainsRune(p, 0) || p == "" {
		return "", "", errors.New("pattern expands to an unusable path")
	}
	if !path.IsAbs(p) {
		p = path.Clean(p)
		if p == "." || p == ".." || strings.HasPrefix(p, "../") {
			return "", "", errors.New("path leaves the home directory")
		}
		return p, "", nil
	}
	p = path.Clean(p)
	if strings.HasPrefix(p, a.home+"/") {
		return strings.TrimPrefix(p, a.home+"/"), "", nil
	}
	return "", p, nil
}

// parseSSHDRaw reads "sshd -T" output into keyword -> values, keeping the case
// of the values (paths are case sensitive).
func parseSSHDRaw(out string) (map[string][]string, error) {
	values := map[string][]string{}
	for i, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		kw, rest, _ := strings.Cut(line, " ")
		if !sshdKeyword.MatchString(kw) {
			return nil, fmt.Errorf("line %d is not a keyword line: %q", i+1, clean(line, 60))
		}
		values[kw] = append(values[kw], strings.TrimSpace(rest))
	}
	if len(values) == 0 {
		return nil, errors.New("empty output")
	}
	return values, nil
}

type authKey struct {
	typ, fp string
	line    int
}

type badLine struct {
	n   int
	why string
}

// parseAuthorizedKeys reads an authorized keys file. Blank lines and comment
// lines are skipped; every other line is a key or reported in bad, with a
// reason from a fixed set.
func parseAuthorizedKeys(content string) (keys []authKey, bad []badLine) {
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		if len(line) > maxKeyLine {
			bad = append(bad, badLine{i + 1, "line is too long"})
			continue
		}
		typ, fp, err := keyFingerprint(trimmed)
		if err != nil {
			bad = append(bad, badLine{i + 1, err.Error()})
			continue
		}
		keys = append(keys, authKey{typ: typ, fp: fp, line: i + 1})
	}
	return keys, bad
}

var keyTypeRe = regexp.MustCompile(`^(?:ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$`)

// keyFingerprint returns the key type and the "SHA256:..." fingerprint of an
// authorized_keys line (without leading blanks). The error text is one of a
// fixed set and never quotes the line.
func keyFingerprint(line string) (typ, fp string, err error) {
	rest := line
	first, after := splitToken(rest)
	if !keyTypeRe.MatchString(first) {
		// Options come first; they may hold quoted blanks.
		end, ok := optionsEnd(rest)
		if !ok {
			return "", "", errors.New("unterminated quote in the options")
		}
		rest = strings.TrimLeft(rest[end:], " \t")
		first, after = splitToken(rest)
	}
	if !keyTypeRe.MatchString(first) {
		return "", "", errors.New("no known key type")
	}
	b64, _ := splitToken(strings.TrimLeft(after, " \t"))
	if b64 == "" {
		return "", "", errors.New("no key data")
	}
	blob, derr := base64.StdEncoding.DecodeString(b64)
	if derr != nil || len(blob) == 0 || len(blob) > maxKeyBlob {
		return "", "", errors.New("key data is not valid base64 or has an unusable size")
	}
	if n, ok := wireString(blob); !ok || n != first {
		return "", "", errors.New("key data does not match the key type")
	}
	sum := sha256.Sum256(blob)
	return first, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// splitToken returns the first blank-delimited token and the rest.
func splitToken(s string) (string, string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// optionsEnd returns the index of the first blank outside quotes, the end of
// the options field, and false when a quote is not closed.
func optionsEnd(s string) (int, bool) {
	in := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && in && i+1 < len(s):
			i++
		case c == '"':
			in = !in
		case (c == ' ' || c == '\t') && !in:
			return i, true
		}
	}
	return len(s), !in
}

// wireString reads the leading SSH wire-format string (uint32 length, bytes)
// of a key blob.
func wireString(blob []byte) (string, bool) {
	if len(blob) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(blob)
	if n > uint32(len(blob)-4) {
		return "", false
	}
	return string(blob[4 : 4+n]), true
}
