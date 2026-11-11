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
// A line is read the way OpenSSH reads it (see keyFingerprint, which ports
// sshkey_advance_past_options): the line ends at a NUL byte, a key at the start
// of the line is used as it stands, otherwise the options are stepped over
// (quotes can hold blanks, a backslash escapes a quote, an unterminated quote
// is an unparseable line) and the key must follow. The options are not
// interpreted. The key type must be one of ssh-ed25519, ssh-rsa, ssh-dss,
// ecdsa-sha2-nistp256/384/521 and the two sk- types, the base64 blob must
// decode (strictly, as OpenSSH does) to a well-formed key of that type, and a
// comment is ignored whatever its length (a line of any length up to the 256
// KiB file limit is read in full, so a long comment cannot hide a key). A
// certificate (a -cert-v01 type) is not a key to compare and counts as a line
// that is not a key. The fingerprint is the unpadded base64 of the SHA-256 of
// the blob, computed here; it is the one "ssh-keygen -l" prints for the same
// line (the tests compare them for lines captured with ssh-keygen on Ubuntu
// 22.04 and 24.04). A line that is not blank, not a comment and not a key is a
// warning.
//
// A path in the home that leads out of it through a symbolic link is not
// followed (a warning with the reason), although sshd follows such a link and
// would accept the keys in the file. That is a limit: the keys are never
// judged as pass, but they are not listed either. An AuthorizedKeysFile outside
// the home that is reached through links is read only when every directory on
// the way is root-owned and not writable by others (ReadTrusted); the user can
// not point such a path at a file of their own.
//
// Result: a key in a file that the user's expected list does not have is a
// fail (subject "<user>:SHA256:..."), also for a user without any expected
// entry. Without a fail, an expected key that no file has (same subject form),
// a file that was refused or has unparseable lines (subject
// "<user>:<path>" or "<user>:<path>:<line>"), a passwd line that does not
// parse (anything but exactly seven fields; its user is not examined), an expected user without an account, and an AuthorizedKeysCommand
// other than none (subject "authorizedkeyscommand", its keys cannot be
// checked) make the status warn. When there is a fail, the warnings are
// counted in the summary and not listed, because every evidence item of a
// failing result is a failing item. The warnings of a failing result are
// carried separately as well (Outcome.Warnings): an exception that covers
// every unexpected key leaves the check as a warn with those warnings, not as
// excepted. A user who makes their own file unreadable or unusable gets a
// warning, never a pass.
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
				Detail:  "AuthorizedKeysCommand is set (" + show(cmdVals[0]) + "); the keys it supplies cannot be checked",
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
	unreadable := 0 // fails that are lines which start with a key type but cannot be read
	total := 0
	for _, a := range accounts {
		if !a.has {
			continue
		}
		found := map[string]string{} // fingerprint -> detail
		for _, pattern := range files {
			rel, abs, perr := expandKeyPath(pattern, a)
			if perr != nil {
				warns = append(warns, result.Evidence{Subject: a.name + ":" + pattern, Detail: perr.Error()})
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
				warns = append(warns, result.Evidence{Subject: a.name + ":" + shown, Detail: "not read: " + keyReadReason(rerr)})
				continue
			}
			keys, bad := parseAuthorizedKeys(string(data))
			for _, line := range bad {
				ev := result.Evidence{
					Subject: fmt.Sprintf("%s:%s:%d", a.name, shown, line.n),
					Detail:  "line is not a public key: " + line.why,
				}
				if line.keyish {
					// sshd may accept a key from this line: it is not a harmless line
					ev.Detail = "line starts with a key type that sshd reads, but it cannot be read here (" + line.why + "), so it may hold an unchecked key"
					unreadable++
					fails = append(fails, ev)
					continue
				}
				warns = append(warns, ev)
			}
			for _, k := range keys {
				if _, dup := found[k.fp]; !dup {
					found[k.fp] = fmt.Sprintf("%s key in %s line %d", k.typ, show(shown), k.line)
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
		shown, _, set := limitEvidence(fails)
		o := partialError(causes, fails)
		o.Evidence, o.Set = shown, set
		return o
	case len(fails) > 0:
		shown, hidden, set := limitEvidence(fails)
		what := fmt.Sprintf("%d unexpected authorized key(s)", len(fails))
		if unreadable > 0 {
			what += fmt.Sprintf(" (%d of them lines that start with a key type but cannot be read)", unreadable)
		}
		s := what + ": " + subjectList(shown, 5)
		if len(warns) > 0 {
			s += fmt.Sprintf("; also %d warning(s): %s", len(warns), subjectList(sortedEvidence(warns), 5))
		}
		shownWarns, _, warnSet := limitEvidence(warns)
		return Outcome{Status: result.Fail, Summary: s + moreNote(hidden), Evidence: shown, Set: set, Warnings: shownWarns, WarningsSet: warnSet}
	case len(warns) > 0:
		shown, hidden, set := limitEvidence(warns)
		return Outcome{
			Status:   result.Warn,
			Summary:  fmt.Sprintf("no unexpected authorized keys, but %d thing(s) need a look: %s", len(warns), subjectList(shown, 5)) + moreNote(hidden),
			Evidence: shown,
			Set:      set,
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
		s = append(s, show(e.Subject))
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
	return show(err.Error())
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
	// keyish: the line starts with the name of a key type that sshd reads (as
	// the first word, or as the first word after the options), so sshd may
	// well accept a key from it although it could not be read here.
	keyish bool
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
		typ, fp, keyish, err := keyFingerprint(trimmed)
		if err != nil {
			bad = append(bad, badLine{n: i + 1, why: err.Error(), keyish: keyish})
			continue
		}
		keys = append(keys, authKey{typ: typ, fp: fp, line: i + 1})
	}
	return keys, bad
}

// keyBlobTypes are the key type names that sshd reads at the start of a key
// in an authorized keys file, with the type name that the key's blob carries.
// The list is the table of key types in sshkey.c (keytypes[] in OpenSSH 8.9,
// the implementations in keyimpls[] in 9.6) for plain keys: sshkey_read
// matches the name with peek_type_nid, which compares the whole word byte for
// byte against the name of each type. So the match is case sensitive, and the
// short names that sshkey_type_from_name accepts case-insensitively (ED25519,
// RSA, ECDSA, ...) are not key types in this file. Three names differ from the
// blob's: rsa-sha2-256 and rsa-sha2-512 stand for an ssh-rsa key, and
// webauthn-sk-ecdsa-sha2-nistp256@openssh.com for an sk-ecdsa one. XMSS is not
// compiled into the Ubuntu 22.04 and 24.04 packages. A certificate type
// (-cert-v01@openssh.com) is read by sshd as well, but it never matches a key
// that logs in, so such a line is reported as not being a key.
var keyBlobTypes = map[string]string{
	"ssh-ed25519":                        "ssh-ed25519",
	"sk-ssh-ed25519@openssh.com":         "sk-ssh-ed25519@openssh.com",
	"ssh-rsa":                            "ssh-rsa",
	"rsa-sha2-256":                       "ssh-rsa",
	"rsa-sha2-512":                       "ssh-rsa",
	"ssh-dss":                            "ssh-dss",
	"ecdsa-sha2-nistp256":                "ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384":                "ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521":                "ecdsa-sha2-nistp521",
	"sk-ecdsa-sha2-nistp256@openssh.com": "sk-ecdsa-sha2-nistp256@openssh.com",
	"webauthn-sk-ecdsa-sha2-nistp256@openssh.com": "sk-ecdsa-sha2-nistp256@openssh.com",
}

// The reasons a line is not a key. They are fixed texts: a reason never quotes
// the line.
var (
	errNoKeyType = errors.New("no known key type")
	errNoKeyData = errors.New("no key data")
	errBadBlob   = errors.New("key data is not valid base64 or is not a key of that type")
	errQuote     = errors.New("unterminated quote in the options")
)

// keyFingerprint returns the key type and the "SHA256:..." fingerprint of an
// authorized_keys line (without leading blanks), reading the line the way
// OpenSSH does (check_authkey_line in auth2-pubkey.c of OpenSSH 8.9, the same
// function in auth2-pubkeyfile.c of 9.6, and do_fingerprint in ssh-keygen.c,
// which lists the same key):
//
//  1. The line is a C string: it ends at the first NUL byte.
//  2. A key is read at the start of the line (sshkey_read): a key type, blanks,
//     and a base64 blob that ends at the next blank. What follows, the
//     comment, is not looked at.
//  3. Only when that fails, the options are skipped (sshkey_advance_past_options,
//     see advancePastOptions) and a key is read after the blanks that follow
//     them.
//
// The key sshd would use and the key listed here are therefore the same key
// for every line: the options are not parsed or trusted, they are only
// stepped over exactly as sshd steps over them, so text inside quotes can
// neither hide a key from this check nor make up one. A line that sshd would
// refuse because of an unknown or malformed option is still listed (OpenSSH
// applies the option rules after finding the key); the worst case is a key
// that is listed although it cannot log in.
//
// keyish is true for a line that cannot be read although it starts, as its
// first word or as the first word after the options, with the name of a key
// type that sshd reads (keyBlobTypes): sshd may accept a key from such a line
// that this code does not understand, so the caller must not treat it as a
// harmless line.
func keyFingerprint(line string) (typ, fp string, keyish bool, err error) {
	if i := strings.IndexByte(line, 0); i >= 0 {
		line = line[:i]
	}
	typ, fp, err = readKey(line)
	if err == nil {
		return typ, fp, false, nil
	}
	first, _ := splitToken(line)
	_, firstIsKey := keyBlobTypes[first]
	end, ok := advancePastOptions(line)
	if !ok {
		// the quote opens inside the first word, which is then no key type
		return "", "", false, errQuote
	}
	after := strings.TrimLeft(line[end:], " \t")
	typ2, fp2, err2 := readKey(after)
	if err2 == nil {
		return typ2, fp2, false, nil
	}
	nextWord, _ := splitToken(after)
	_, nextIsKey := keyBlobTypes[nextWord]
	if firstIsKey {
		return "", "", true, err // the line starts with a key type, so that is the problem
	}
	return "", "", nextIsKey, err2
}

// readKey mirrors sshkey_read: a key type, blanks, a base64 blob. s is a
// C string without NUL.
func readKey(s string) (typ, fp string, err error) {
	typ, rest := splitToken(s)
	blobType, known := keyBlobTypes[typ]
	if !known {
		return "", "", errNoKeyType
	}
	b64, _ := splitToken(strings.TrimLeft(rest, " \t"))
	if b64 == "" {
		return "", "", errNoKeyData
	}
	// sshbuf_b64tod -> b64_pton skips every isspace byte anywhere in the text
	// (the word ends only at a blank or a tab, so \v, \f and \r stay in it),
	// then decodes strictly: padding is required, bits past the last byte must
	// be zero.
	b64 = strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ':
			return -1
		}
		return r
	}, b64)
	blob, derr := base64.StdEncoding.Strict().DecodeString(b64)
	if derr != nil || len(blob) == 0 || len(blob) > maxKeyBlob {
		return "", "", errBadBlob
	}
	canon, ok := canonicalBlob(blobType, blob)
	if !ok {
		return "", "", errBadBlob
	}
	sum := sha256.Sum256(canon)
	return typ, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// splitToken returns the first blank-delimited token and the rest. The blanks
// are space and tab, like OpenSSH's strcspn(cp, " \t").
func splitToken(s string) (string, string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// advancePastOptions returns the index of the end of the key options at the
// start of s: the first space or tab that is not inside double quotes, or
// len(s). It is a line-for-line port of sshkey_advance_past_options
// (authfile.c); in particular a backslash only matters when a double quote
// follows it, in which case both are skipped, and it matters outside quotes
// too. ok is false for an unterminated quote.
func advancePastOptions(s string) (end int, ok bool) {
	quoted := false
	i := 0
	for ; i < len(s) && (quoted || (s[i] != ' ' && s[i] != '\t')); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
			i++ // skip both
		} else if s[i] == '"' {
			quoted = !quoted
		}
	}
	return i, !(i == len(s) && quoted)
}

// innerTypeOK reports whether name, the type string at the start of a blob,
// is one that OpenSSH takes for the key type typ (the name sshkey_to_blob
// writes). sshkey_from_blob_internal looks the string up with
// sshkey_type_from_name, which accepts every name of the type (an ssh-rsa key
// may call itself rsa-sha2-256) and, for the plain types, the short name in any
// case ("RSA", "ed25519"). For the ECDSA types the name must be exact: the
// curve is derived from it by sshkey_ecdsa_nid_from_name.
func innerTypeOK(typ, name string) bool {
	switch typ {
	case "ssh-rsa":
		if name == "ssh-rsa" || name == "rsa-sha2-256" || name == "rsa-sha2-512" {
			return true
		}
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		if name == typ || name == "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" {
			return true
		}
	default:
		if name == typ {
			return true
		}
	}
	short := map[string]string{"ssh-ed25519": "ED25519", "sk-ssh-ed25519@openssh.com": "ED25519-SK", "ssh-rsa": "RSA", "ssh-dss": "DSA"}[typ]
	return short != "" && strings.EqualFold(name, short)
}

// canonicalBlob checks that blob is exactly the wire format OpenSSH reads for
// the key type (the type name first, then the fields of the type, nothing
// after them) and returns the blob as OpenSSH writes the key back, which is
// what its fingerprint is computed over (sshkey_fingerprint serialises the
// parsed key; it does not hash the text it read). The two differ for the
// integers of RSA and DSA keys: they are read after dropping any number of
// leading zero bytes and written with the fewest bytes, plus one zero byte in
// front when the top bit is set (sshbuf_get_bignum2_bytes_direct,
// sshbuf_put_bignum2). A blob with a padded integer is a key that sshd
// accepts and ssh-keygen lists under the fingerprint of the canonical form. An
// integer with its top bit set and no zero byte before it is negative, and
// refused, as are integers over 2048 bytes. The other types have no integers
// (an EC point is a string, and must be an uncompressed point of the curve's
// size). ok is false for anything else.
func canonicalBlob(typ string, blob []byte) (canon []byte, ok bool) {
	var fields [][]byte
	for rest := blob; len(rest) > 0; {
		if len(rest) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(rest)
		if n > uint32(len(rest)-4) {
			return nil, false
		}
		fields = append(fields, rest[4:4+n])
		rest = rest[4+n:]
	}
	if len(fields) == 0 || !innerTypeOK(typ, string(fields[0])) {
		return nil, false
	}
	fields[0] = []byte(typ) // written back under the type's own name
	mpints := 0             // fields 1 to mpints are integers
	switch typ {
	case "ssh-ed25519":
		ok = len(fields) == 2 && len(fields[1]) == 32
	case "sk-ssh-ed25519@openssh.com":
		ok = len(fields) == 3 && len(fields[1]) == 32
	case "ssh-rsa":
		ok, mpints = len(fields) == 3, 2
	case "ssh-dss":
		ok, mpints = len(fields) == 5, 4
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		ok = len(fields) == 3 && "ecdsa-sha2-"+string(fields[1]) == typ && ecPointOK(string(fields[1]), fields[2])
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		ok = len(fields) == 4 && string(fields[1]) == "nistp256" && ecPointOK("nistp256", fields[2])
	}
	if !ok {
		return nil, false
	}
	for i := 1; i <= mpints; i++ {
		f, good := canonicalMPInt(fields[i])
		if !good {
			return nil, false
		}
		fields[i] = f
	}
	for _, f := range fields {
		canon = binary.BigEndian.AppendUint32(canon, uint32(len(f)))
		canon = append(canon, f...)
	}
	return canon, true
}

// canonicalMPInt reads an SSH mpint the way sshbuf_get_bignum2_bytes_direct
// does and returns its canonical encoding.
func canonicalMPInt(f []byte) ([]byte, bool) {
	const maxBignum = 16384 / 8
	if len(f) != 0 && f[0]&0x80 != 0 {
		return nil, false // negative
	}
	if len(f) > maxBignum+1 || (len(f) == maxBignum+1 && f[0] != 0) {
		return nil, false
	}
	for len(f) > 0 && f[0] == 0 {
		f = f[1:]
	}
	if len(f) > 0 && f[0]&0x80 != 0 {
		f = append([]byte{0}, f...)
	}
	return f, true
}

// ecPointOK: an uncompressed point (0x04, x, y) with the size of the curve's
// coordinates. OpenSSH also checks that the point lies on the curve, which is
// not done here: a point off the curve is listed although sshd refuses it.
func ecPointOK(curve string, pt []byte) bool {
	size := map[string]int{"nistp256": 32, "nistp384": 48, "nistp521": 66}[curve]
	return size != 0 && len(pt) == 1+2*size && pt[0] == 4
}
