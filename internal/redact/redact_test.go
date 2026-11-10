package redact

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// The fake secrets are assembled at run time so that the source holds no
// string that looks like a real credential to a scanner.
var (
	fakeGitHub = "gh" + "p_" + strings.Repeat("a1B2", 9)
	fakeGHPAT  = "github" + "_pat_" + strings.Repeat("A1b2C3", 5)
	fakeNtfy   = "t" + "k_" + strings.Repeat("a1b2c3d4e5", 3)[:29]
	fakeAWS    = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
	fakeSlack  = "xo" + "xb-" + "123456789012-abcdefghijkl"
	fakeGoogle = "AI" + "za" + strings.Repeat("Ab1_-", 7)
	fakeStripe = "sk" + "_live_" + strings.Repeat("aB3", 8)
	fakeJWT    = "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiJ4In0." + "c2lnbmF0dXJlMTIzNDU2"
	fakeSK     = "s" + "k-" + strings.Repeat("aB3-", 12)
	fakeSKAnt  = "s" + "k-ant-api03-" + strings.Repeat("aB3_", 10)
	fakeGitLab = "gl" + "pat-" + strings.Repeat("aB3_", 5)
	fakeKey    = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\nQyNTUxOQAAACD\n-----END OPENSSH PRIVATE KEY-----"
)

// positives: text that holds a secret. secret must not survive; keep must.
var positives = []struct {
	name, in, secret, keep string
}{
	{"private key block", "key: " + fakeKey + " end", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU", "key: [REDACTED private key] end"},
	{"rsa private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEA", "[REDACTED private key]"},
	{"encrypted private key", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkq\n-----END ENCRYPTED PRIVATE KEY-----", "MIIFHDBOBgkq", "[REDACTED private key]"},
	{"private key cut off", "head -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg", "MIIEvQIBADANBg", "head [REDACTED private key]"},
	{"two private keys", fakeKey + " and " + fakeKey, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU", "[REDACTED private key] and [REDACTED private key]"},
	{"password equals", "mysql --user=root password=hunter2 --host=x", "hunter2", "password=[REDACTED] --host=x"},
	{"password colon", "password: hunter2", "hunter2", "password: [REDACTED]"},
	{"upper case name", "DB_PASSWORD=hunter2", "hunter2", "DB_PASSWORD=[REDACTED]"},
	{"passwd", "passwd=hunter2", "hunter2", "passwd=[REDACTED]"},
	{"passphrase", "passphrase = correct horse", "correct", "passphrase = [REDACTED] horse"},
	{"secret", "client_secret=abcDEF123", "abcDEF123", "client_secret=[REDACTED]"},
	{"token", "api_token=abcDEF123456", "abcDEF123456", "api_token=[REDACTED]"},
	{"api key", "x-api-key: abcDEF123456", "abcDEF123456", "x-api-key: [REDACTED]"},
	{"apikey", "APIKEY=abcDEF123456", "abcDEF123456", "APIKEY=[REDACTED]"},
	{"access key", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "AWS_SECRET_ACCESS_KEY=[REDACTED]"},
	{"private key setting", "private_key=abc123def456", "abc123def456", "private_key=[REDACTED]"},
	{"credentials", "credentials=user:pw", "user:pw", "credentials=[REDACTED]"},
	{"double quoted value", `password="two words here" next`, "two words here", `password=[REDACTED] next`},
	{"single quoted value", `token='abc def' next`, "abc def", `token=[REDACTED] next`},
	{"json", `{"password": "hunter2", "user": "bob"}`, "hunter2", `{"password": [REDACTED], "user": "bob"}`},
	{"json secret key", `{"client_secret":"s3cr3t-value"}`, "s3cr3t-value", `{"client_secret":[REDACTED]}`},
	{"query string", "https://host/path?token=abc123&x=1", "abc123", "token=[REDACTED]&x=1"},
	{"env style list", "FOO=1 SECRET=abc BAR=2", "abc", "SECRET=[REDACTED] BAR=2"},
	{"flag with space", "curl --password hunter2 --silent", "hunter2", "--password [REDACTED] --silent"},
	{"short flag", "tool -token abcdef", "abcdef", "-token [REDACTED]"},
	{"api-key flag", "run --api-key abc123", "abc123", "--api-key [REDACTED]"},
	{"bearer", "Authorization: Bearer abcdef0123456789abcdef", "abcdef0123456789abcdef", "Authorization: [REDACTED]"},
	{"authorization basic", "authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz", "authorization=[REDACTED]"},
	{"authorization json", `"Authorization": "Bearer abc.def.ghi"`, "abc.def.ghi", `"Authorization": [REDACTED]`},
	{"bare bearer", "sent bearer abcdef0123456789abcdef.xyz to host", "abcdef0123456789abcdef", "bearer [REDACTED]"},
	{"url userinfo", "pull https://bob:s3cret@registry.example.com/img", "s3cret", "https://[REDACTED]@registry.example.com/img"},
	{"url token userinfo", "git clone https://" + fakeGitHub + "@github.example/repo.git", fakeGitHub, "https://[REDACTED]@github.example/repo.git"},
	{"url userinfo other scheme", "postgres://app:pw123@db.example:5432/app", "pw123", "postgres://[REDACTED]@db.example:5432/app"},
	{"aws key id", "key " + fakeAWS + " found", fakeAWS, "key [REDACTED] found"},
	{"github token", "token is " + fakeGitHub, fakeGitHub, "token is [REDACTED]"},
	{"github pat", "using " + fakeGHPAT, fakeGHPAT, "using [REDACTED]"},
	{"ntfy token", "ntfy auth " + fakeNtfy + " ok", fakeNtfy, "ntfy auth [REDACTED] ok"},
	{"slack token", "slack " + fakeSlack, fakeSlack, "slack [REDACTED]"},
	{"google key", "key " + fakeGoogle, fakeGoogle, "key [REDACTED]"},
	{"stripe key", "stripe " + fakeStripe, fakeStripe, "stripe [REDACTED]"},
	{"jwt", "jwt " + fakeJWT + " end", fakeJWT, "jwt [REDACTED] end"},
	{"two secrets in one text", "password=one token=two", "one", "password=[REDACTED] token=[REDACTED]"},
	{"multi line", "a\npassword=hunter2\nb", "hunter2", "a\npassword=[REDACTED]\nb"},

	// Env-style names: the secret word is the last word of the name.
	{"secret key", "SECRET_KEY=hunter2 next", "hunter2", "SECRET_KEY=[REDACTED] next"},
	{"secret-key lower", "secret-key: hunter2", "hunter2", "secret-key: [REDACTED]"},
	{"auth key", "AUTH_KEY=hunter2", "hunter2", "AUTH_KEY=[REDACTED]"},
	{"auth key, colon", "auth-key: hunter2", "hunter2", "auth-key: [REDACTED]"},
	{"auth key, no separator", "authkey=hunter2", "hunter2", "authkey=[REDACTED]"},
	{"signing key, colon", "signing_key: hunter2", "hunter2", "signing_key: [REDACTED]"},
	{"encryption key, colon", "encryption-key: hunter2", "hunter2", "encryption-key: [REDACTED]"},
	{"master key", "master_key=hunter2", "hunter2", "master_key=[REDACTED]"},
	{"master key, colon, no separator", "masterkey: hunter2", "hunter2", "masterkey: [REDACTED]"},
	{"signing key", "SIGNING_KEY=hunter2", "hunter2", "SIGNING_KEY=[REDACTED]"},
	{"encryption key", "ENCRYPTION_KEY=hunter2", "hunter2", "ENCRYPTION_KEY=[REDACTED]"},
	{"db pass", "DB_PASS=hunter2", "hunter2", "DB_PASS=[REDACTED]"},
	{"mysql pwd", "MYSQL_PWD=hunter2 mysql", "hunter2", "MYSQL_PWD=[REDACTED] mysql"},
	{"pwd alone", "pwd=hunter2", "hunter2", "pwd=[REDACTED]"},
	{"pwd after a space", "run pwd=hunter2", "hunter2", "run pwd=[REDACTED]"},
	{"pass colon", "db.pass: hunter2", "hunter2", "db.pass: [REDACTED]"},
	{"env key suffix", "STRIPE_KEY=hunter2", "hunter2", "STRIPE_KEY=[REDACTED]"},
	{"env token suffix", "DEPLOY_TOKEN=hunter2", "hunter2", "DEPLOY_TOKEN=[REDACTED]"},
	{"env secret suffix", "OAUTH_CLIENT_SECRET=hunter2", "hunter2", "OAUTH_CLIENT_SECRET=[REDACTED]"},
	{"env list", "A=1 DB_PASS=hunter2 B=2", "hunter2", "DB_PASS=[REDACTED] B=2"},

	// Cookies: the whole header value.
	{"cookie", "Cookie: theme=dark; session=abcdef", "abcdef", "Cookie: [REDACTED]"},
	{"set-cookie", "Set-Cookie: theme=dark; sid=abcdef; HttpOnly", "abcdef", "Set-Cookie: [REDACTED]"},
	{"cookie lower case, equals", "cookie=a=1;sid=abcdef", "abcdef", "cookie=[REDACTED]"},
	{"cookie in a header block", "Host: x\ncookie: sid=abcdef\nAccept: */*", "abcdef", "cookie: [REDACTED]\nAccept: */*"},

	// More token shapes.
	{"sk key", "key " + fakeSK + " end", fakeSK, "key [REDACTED] end"},
	{"sk-ant key", "key " + fakeSKAnt + " end", fakeSKAnt, "key [REDACTED] end"},
	{"gitlab token", "using " + fakeGitLab + " end", fakeGitLab, "using [REDACTED] end"},

	// PEM headers in any case.
	{"pem lower case", "-----begin rsa private key-----\nMIIabc\n-----end rsa private key-----", "MIIabc", "[REDACTED private key]"},
	{"pem mixed case, cut off", "x -----Begin Private Key-----\nMIIabc", "MIIabc", "x [REDACTED private key]"},

	// Quoted values with backslash escapes, and quotes that never close.
	{"escaped quote in a value", `password="a\"bc" next`, "bc", `password=[REDACTED] next`},
	{"escaped quote, single quotes", `token='a\'bc' next`, "bc", `token=[REDACTED] next`},
	{"escaped backslash at the end", `password="ab\\" next`, "ab", `password=[REDACTED] next`},
	{"quote that is never closed", `password="abc def`, "abc", `password=[REDACTED]`},
	{"quote that is never closed, ends in a backslash", `password="abc\`, "abc", `password=[REDACTED]`},
	{"apostrophe inside a value", "password=hun'ter2 next", "ter2", "password=[REDACTED] next"},

	// User info up to the last @ before the host.
	{"url password with an at sign", "https://user:p@ssw0rd@host.example/x", "ssw0rd", "https://[REDACTED]@host.example/x"},
	{"url user info with two at signs", "git clone https://a@b:c@d@host.example/repo", "c@d", "https://[REDACTED]@host.example/repo"},
	{"url empty user, password", "redis://:hunter2@host.example:6379/0", "hunter2", "redis://[REDACTED]@host.example:6379/0"},

	// A NUL byte separates command line arguments like a space.
	{"flag, NUL before the value", "--password\x00hunter2\x00--host\x00x", "hunter2", "--password\x00[REDACTED]\x00--host\x00x"},
	{"short flag, NUL before the value", "tool\x00-token\x00hunter2", "hunter2", "-token\x00[REDACTED]"},
	{"value ends at a NUL", "mysql\x00--password=hunter2\x00--host=x", "hunter2", "--password=[REDACTED]\x00--host=x"},
	{"flag at the start", "--password hunter2", "hunter2", "--password [REDACTED]"},
	{"single dash flag", "tool -password hunter2", "hunter2", "-password [REDACTED]"},
	{"flag with a prefix", "tool --db-password hunter2 x", "hunter2", "--db-password [REDACTED] x"},
	{"api-key flag after a command", "cmd --api-key hunter2", "hunter2", "--api-key [REDACTED]"},
	{"quoted flag", `cmd "--token" hunter2`, "hunter2", `"--token" [REDACTED]`},
	{"single quoted flag", `cmd '--token' hunter2`, "hunter2", `'--token' [REDACTED]`},
	{"flag after an equals sign", "x=--password hunter2", "hunter2", "x=--password [REDACTED]"},
	{"flag after a paren", "(--password hunter2)", "hunter2", "(--password [REDACTED]"},
	{"flag after a bracket", "[--password hunter2]", "hunter2", "[--password [REDACTED]"},
	{"flag after a comma", "a,--password hunter2", "hunter2", "a,--password [REDACTED]"},
	{"flag after a newline", "a\n--password hunter2", "hunter2", "a\n--password [REDACTED]"},
	{"flag after a semicolon", "a;--token hunter2", "hunter2", "a;--token [REDACTED]"},
	{"triple dash flag", "tool ---password hunter2", "hunter2", "---password [REDACTED]"},
	{"flag at the start, NUL", "--password\x00hunter2", "hunter2", "--password\x00[REDACTED]"},
	{"two flags", "--password a --token b", "b", "--password [REDACTED] --token [REDACTED]"},
	{"flag after an identifier with a flag-like word", "prohibit-password --password hunter2", "hunter2", "prohibit-password --password [REDACTED]"},
}

// negatives: text that has the look of a secret but is none, plus the shapes
// our own probes print. It must pass unchanged.
var negatives = []string{
	"passwordauthentication yes",
	"openssl 3.0.2-0ubuntu1.18",
	"libssl3 3.0.2-0ubuntu1.18 amd64",
	"SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
	"alice:SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
	"token_file /etc/keepwatch/token",
	"bypass=1",
	"compass: north",
	"passes: 3",
	"/usr/bin/pwd",
	"pwdx 1234",
	"pwd",
	"ssh_host_key_algorithms ssh-ed25519",
	"authorized_keys:3",
	"/home/alice/.ssh/authorized_keys:3",
	"monkey=banana",
	"https://example.com/path@user",
	"https://example.com?next=a@b",
	"a cookie jar",
	"effective value: yes; allowed: no",
	"passwordauthentication: no",
	"permitemptypasswords no",
	"token_file: /etc/keepwatch/ntfy.token",
	"kbdinteractiveauthentication no",
	"PermitRootLogin prohibit-password",
	"prohibit-password or without-password",
	"no-password login",
	"without-password or no",
	"no or prohibit-password or without-password",
	"sshd permitrootlogin is yes, expected no or prohibit-password or without-password",
	"sshd passwordauthentication is yes, expected no",
	"sshd kbdinteractiveauthentication is yes, expected no",
	"sshd x11forwarding is yes, expected no",
	"effective value: yes; allowed: no, prohibit-password, without-password",
	"effective value: yes; allowed: no",
	"x-token value",
	"pre--password value",
	"a---token value",
	"my_-password value",
	"authorized_keys: /home/deploy/.ssh/authorized_keys",
	"user:SHA256:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek",
	"tcp/0.0.0.0:8080",
	"udp/[fe80::1]%eth0:546",
	"fail2ban.service",
	"state: inactive",
	"CN example.com, not after 2026-12-01, 20 days left",
	"/var/run/reboot-required",
	"(7 more not shown)",
	"7 further items are not listed, the limit is 100 items",
	"package lists are 3 hours old; limit is 48 hours",
	"docker.sock mounted into container web",
	"a basic configuration of the secretary",
	"the bearer of this message",
	"a token of appreciation",
	"https://example.com/path?x=1",
	"ssh://example.com:22/repo",
	"contact: admin@example.com",
	"mailto:admin@example.com",
	"password",
	"password was changed",
	"password: ",
	"--password-stdin",
	"tool --password --verbose",
	"--token-file /etc/token",
	"tk_short",
	"gh" + "p_short",
	"s" + "k-short",
	"gl" + "pat-short",
	"desk-" + strings.Repeat("a", 30),
	"risk-assessment-for-the-whole-production-system",
	"AKIA-not-a-key",
	"id: 0123456789abcdef0123456789abcdef",
	"sha256:" + strings.Repeat("ab", 32),
	"héllo wörld, 日本語",
	"",
}

func TestPositivesAreRedacted(t *testing.T) {
	r := Default()
	for _, p := range positives {
		t.Run(p.name, func(t *testing.T) {
			got := r.Redact(p.in)
			if strings.Contains(got, p.secret) {
				t.Errorf("secret %q survived in %q", p.secret, got)
			}
			if !strings.Contains(got, p.keep) {
				t.Errorf("Redact(%q)\n got %q\nwant it to contain %q", p.in, got, p.keep)
			}
			if again := r.Redact(got); again != got {
				t.Errorf("not idempotent: %q then %q", got, again)
			}
			if clean := r.Clean(p.in); strings.Contains(clean, p.secret) {
				t.Errorf("Clean leaks the secret: %q", clean)
			}
		})
	}
}

func TestNegativesAreUntouched(t *testing.T) {
	r := Default()
	for _, in := range negatives {
		if got := r.Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestNilRedactorUsesTheBuiltIns(t *testing.T) {
	var r *Redactor
	if got := r.Clean("password=x"); got != "password=[REDACTED]" {
		t.Errorf("Clean = %q", got)
	}
}

func TestExtraPatterns(t *testing.T) {
	r, err := New([]string{`corp-[0-9]{4}`, `session=([a-z]+);`, `(?i)internal-host-\w+`})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"id corp-1234 end":            "id [REDACTED] end",
		"cookie session=abcdef; path": "cookie session=[REDACTED]; path", // only the group
		"at Internal-Host-Alpha now":  "at [REDACTED] now",
		"corp-1111 corp-2222":         "[REDACTED] [REDACTED]",
		"nothing here":                "nothing here",
		"password=x corp-1234":        "password=[REDACTED] [REDACTED]", // built-ins still apply
	}
	for in, want := range cases {
		if got := r.Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtraPatternWithAnOptionalGroupThatDidNotMatch(t *testing.T) {
	r, err := New([]string{`key(=(\w+))?`})
	if err != nil {
		t.Fatal(err)
	}
	// The first group is "=value"; without it the whole match is replaced.
	if got := r.Redact("key=abc and key"); got != "key[REDACTED] and [REDACTED]" {
		t.Errorf("got %q", got)
	}
}

func TestExtraPatternThatCanMatchEmptyDoesNotMangleText(t *testing.T) {
	// ValidatePattern rejects patterns that match "", but a pattern can
	// match empty at some positions only. Empty matches are skipped.
	re := mustCompile(t, `x*`)
	if got := replaceExtra(re, "abc"); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := replaceExtra(re, "axxb"); got != "a[REDACTED]b" {
		t.Errorf("got %q", got)
	}
}

func TestValidatePattern(t *testing.T) {
	bad := map[string]string{
		"":                                   "must not be empty",
		"(":                                  "valid regular expression",
		"[a-":                                "valid regular expression",
		`(?=x)`:                              "valid regular expression", // RE2 has no lookahead
		`a*`:                                 "empty string",
		`^`:                                  "empty string",
		`(a|)`:                               "empty string",
		strings.Repeat("a", MaxPatternLen+1): "limit is 256",
		`a{1001}`:                            "valid regular expression",
		// Valid, and small as text, but a program of thousands of
		// instructions that runs on every byte of every field.
		`(a|b|c|d|e){1000}x`:                       "3003 instructions, the limit is 1000",
		`[^x]{1000}[^y]{1000}x`:                    "too complex",
		`[a-z]{300}[0-9]{300}[A-Z]{300}[ -~]{300}`: "too complex",
		`a{1000}`:                              "too complex",
		fmt.Sprintf("a{%d}", MaxProgramSize-1): "1001 instructions", // one over the limit
	}
	for p, want := range bad {
		err := ValidatePattern(p)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidatePattern(%q) = %v, want an error containing %q", p, err, want)
		}
	}
	for _, p := range []string{`a`, `corp-\d+`, `(?i)secret`, strings.Repeat("a", MaxPatternLen), `[A-Z]{3}-[0-9]{6}`,
		`[a-f0-9]{64}`, `(?:[A-Za-z0-9]{8}-){4}[A-Za-z0-9]{12}`, `a{900}`, `(a|b|c|d|e){100}x`,
		fmt.Sprintf("a{%d}", MaxProgramSize-2)} {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q) = %v", p, err)
		}
	}
}

func TestNewRejectsBadPatternsAndTooMany(t *testing.T) {
	if _, err := New([]string{"ok", "("}); err == nil || !strings.Contains(err.Error(), "pattern 2") {
		t.Errorf("err = %v", err)
	}
	many := make([]string, MaxPatterns+1)
	for i := range many {
		many[i] = "x"
	}
	if _, err := New(many); err == nil || !strings.Contains(err.Error(), "limit is 32") {
		t.Errorf("err = %v", err)
	}
	if _, err := New(many[:MaxPatterns]); err != nil {
		t.Errorf("exactly %d patterns: %v", MaxPatterns, err)
	}
	if r, err := New(nil); err != nil || r == nil {
		t.Errorf("New(nil) = %v, %v", r, err)
	}
}

func TestRedactionRunsInLinearTime(t *testing.T) {
	// An adversarial text for a backtracking engine; RE2 does not backtrack.
	big := strings.Repeat("password="+strings.Repeat("a", 50)+" ", 20000) + strings.Repeat("-----BEGIN PRIVATE KEY-----", 5000)
	r, err := New([]string{`(a+)+b`})
	if err != nil {
		t.Fatal(err)
	}
	out := r.Redact(big)
	if strings.Contains(out, strings.Repeat("a", 50)) {
		t.Error("secret survived in a large text")
	}
}

func TestCleanOrder(t *testing.T) {
	r := Default()
	// A private key block spans lines: it is redacted before the newlines
	// are escaped, so no line of the key survives.
	got := r.Clean("x\n" + fakeKey + "\ny")
	if got != `x\n[REDACTED private key]\ny` {
		t.Errorf("Clean = %q", got)
	}
	// A value ends at the end of its line: the newline is escaped after the
	// redaction, so it must not become part of the value.
	if got := r.Clean("password=abc\nnext=1"); got != `password=[REDACTED]\nnext=1` {
		t.Errorf("Clean = %q", got)
	}
	// Escape sequences in the text never survive.
	got = r.Clean("evil\x1b[2J\x1b]0;title\x07 done")
	if strings.ContainsAny(got, "\x1b\x07") || !strings.Contains(got, `\x1b[2J`) || !strings.Contains(got, `\x07`) {
		t.Errorf("Clean = %q", got)
	}
}

func TestCleanBoundsTheLength(t *testing.T) {
	r := Default()
	long := strings.Repeat("é", MaxFieldRunes+500)
	got := r.Clean(long)
	if n := utf8.RuneCountInString(got); n != MaxFieldRunes+3 || !strings.HasSuffix(got, "...") {
		t.Errorf("%d runes, suffix %q", n, got[len(got)-5:])
	}
	exact := strings.Repeat("é", MaxFieldRunes)
	if got := r.Clean(exact); got != exact {
		t.Error("a field of exactly the limit was cut")
	}
	ascii := strings.Repeat("a", MaxFieldRunes+1)
	if got := r.Clean(ascii); got != strings.Repeat("a", MaxFieldRunes)+"..." {
		t.Errorf("ascii cut wrong: %d bytes", len(got))
	}
	if got := r.Clean(strings.Repeat("a", MaxFieldRunes)); len(got) != MaxFieldRunes {
		t.Error("an ascii field of exactly the limit was cut")
	}
}

func TestTokenPrefixFamilies(t *testing.T) {
	r := Default()
	var secrets []string
	for _, p := range []string{"AK" + "IA", "AS" + "IA", "AG" + "PA", "AI" + "DA", "AR" + "OA", "AN" + "PA", "AN" + "VA", "AI" + "PA"} {
		secrets = append(secrets, p+"ABCDEFGHIJKLMNOP")
	}
	for _, k := range "pousr" {
		secrets = append(secrets, "gh"+string(k)+"_"+strings.Repeat("a", 36))
	}
	for _, k := range "abeprs" {
		secrets = append(secrets, "xo"+"x"+string(k)+"-"+"1234567890abc")
	}
	for _, k := range []string{"sk", "rk"} {
		for _, e := range []string{"live", "test"} {
			secrets = append(secrets, k+"_"+e+"_"+strings.Repeat("Z9", 8))
		}
	}
	secrets = append(secrets, "tk_"+strings.Repeat("a", 40), "github"+"_pat_"+strings.Repeat("a", 82))
	for _, s := range secrets {
		if got := r.Redact("x " + s + " y"); got != "x [REDACTED] y" {
			t.Errorf("Redact(%q) = %q", s, got)
		}
	}
	// One character short of a token is not one.
	for _, s := range []string{"gh" + "p_" + strings.Repeat("a", 35), "tk_" + strings.Repeat("a", 28), "AK" + "IA" + "ABCDEFGHIJKLMNO", "xo" + "xb-123456789",
		"sk" + "_live_" + strings.Repeat("a", 15), "AI" + "za" + strings.Repeat("a", 34)} {
		if got := r.Redact(s); got != s {
			t.Errorf("Redact(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestSecretWordsInNames(t *testing.T) {
	r := Default()
	for _, name := range []string{"password", "passwd", "passphrase", "secret", "token", "api_key", "api-key", "apikey", "access_key", "access-key", "accesskey",
		"private_key", "private-key", "privatekey", "credential", "credentials", "my_PASSWORD", "x.secret", "Db-Token"} {
		for _, sep := range []string{"=", ": ", " = ", ":"} {
			in := "a " + name + sep + "v4lu3 b"
			if got := r.Redact(in); strings.Contains(got, "v4lu3") || !strings.Contains(got, "[REDACTED] b") {
				t.Errorf("Redact(%q) = %q", in, got)
			}
		}
	}
}

// Hostile text for the built-in patterns: long runs of what each pattern
// starts to match. RE2 does not backtrack, so these end quickly; the test
// pins that no pattern was written in a way that makes them quadratic enough
// to hit the test timeout, and that a secret at the end is still found.
func TestBuiltinPatternsOnAdversarialText(t *testing.T) {
	r := Default()
	for name, in := range map[string]struct {
		text   string
		secret bool // the text ends in a secret that must not survive
	}{
		// an odd number of quotes: the last one is never closed
		"unclosed quotes":     {strings.Repeat(`password="`, 5001) + "hunter2", true},
		"unclosed apostrophe": {strings.Repeat(`token='`, 5001) + "hunter2", true},
		"backslashes":         {`password="` + strings.Repeat(`\\`, 20000) + "hunter2", true},
		"cookies":             {strings.Repeat("cookie: ", 5000) + "hunter2", true},
		"pass names":          {strings.Repeat("pass=", 5000) + "hunter2", true},
		"env keys":            {strings.Repeat("a_key=", 5000) + "hunter2", true},
		"flags with NUL":      {strings.Repeat("--token\x00", 5000) + "hunter2", true},
		"urls":                {strings.Repeat("a://@", 5000), false},
		"user info, no @":     {"https://" + strings.Repeat("a:", 20000), false},
		"long PEM headers":    {strings.Repeat("-----begin ", 5000), false},
	} {
		t.Run(name, func(t *testing.T) {
			if out := r.Redact(in.text); in.secret && strings.Contains(out, "hunter2") {
				t.Errorf("secret survived: %.80q", out)
			}
		})
	}
}

func TestRedactingTwiceChangesNothing(t *testing.T) {
	r := Default()
	for _, in := range []string{
		`password="a\"bc" next`, "Cookie: a=b\nSet-Cookie: c=d", "https://u:p@ss@host/x", "DB_PASS=x pwd=y SECRET_KEY=z",
		`password="unclosed`, "--token\x00abc", "-----begin private key-----\nabc", "s" + "k-" + strings.Repeat("a", 30),
	} {
		once := r.Redact(in)
		if twice := r.Redact(once); twice != once {
			t.Errorf("Redact(%q) = %q, again %q", in, once, twice)
		}
	}
}
