package probes_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func keysProbe(t *testing.T) probes.Probe { return prepare(t, "authorized_keys", nil) }

// execKeys runs the probe with the expected fingerprints of the configuration.
func execKeys(p probes.Probe, r execx.Runner, files probes.FS, expected map[string][]string) probes.Outcome {
	return p.Run(context.Background(), &probes.Env{Runner: r, FS: files, AuthorizedKeys: expected})
}

// keyMaterial is a public key line of a fixture with its fingerprint as
// ssh-keygen printed it.
type keyMaterial struct{ line, fp, typ string }

func loadKey(t *testing.T, v, name string) keyMaterial {
	t.Helper()
	line := strings.TrimSpace(fixtureFile(t, v+"/sshkey_"+name+".pub"))
	f := strings.Fields(fixtureFile(t, v+"/sshkey_"+name+"_fp.stdout"))
	return keyMaterial{line: line, fp: f[1], typ: strings.Fields(line)[0]}
}

func sshdFixture(v, name string) *fake.FakeRunner {
	return newRunner().Add(sshdArgv, v+"/"+name)
}

// keyHost is a host with the captured /etc/passwd and the given files below
// the homes of alice and bob.
func keyHost(t *testing.T, v string, files map[string]string) probestest.FakeFS {
	t.Helper()
	homes := map[string]string{}
	for k, c := range files {
		homes[k] = c
	}
	return probestest.FakeFS{Files: map[string]string{"/etc/passwd": fixtureFile(t, v+"/etc_passwd.stdout")}, Homes: homes}
}

const (
	aliceAK  = "/home/alice\x00.ssh/authorized_keys"
	aliceAK2 = "/home/alice\x00.ssh/authorized_keys2"
	bobAK    = "/home/bob\x00.ssh/authorized_keys"
	rootAK   = "/root\x00.ssh/authorized_keys"
)

func TestAuthorizedKeysFingerprintsMatchSSHKeygen(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			ed, rsa, ec := loadKey(t, v, "ed25519"), loadKey(t, v, "rsa"), loadKey(t, v, "ecdsa")
			fsys := keyHost(t, v, map[string]string{aliceAK: ed.line + "\n" + rsa.line + "\n" + ec.line + " comment with spaces\n"})
			exp := map[string][]string{"alice": {ed.fp, rsa.fp, ec.fp}}
			o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, exp)
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "all 3 authorized key(s)")

			// every key is checked against ssh-keygen's number alone
			for _, k := range []keyMaterial{ed, rsa, ec} {
				fsys := keyHost(t, v, map[string]string{aliceAK: k.line + "\n"})
				o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {k.fp}})
				wantStatus(t, o, result.Pass)
			}
		})
	}
}

func TestAuthorizedKeysFailAndWarn(t *testing.T) {
	v := "ubuntu2404"
	ed, rsa, ec := loadKey(t, v, "ed25519"), loadKey(t, v, "rsa"), loadKey(t, v, "ecdsa")
	run := func(files map[string]string, exp map[string][]string) probes.Outcome {
		return execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), keyHost(t, v, files), exp)
	}
	t.Run("an unexpected key fails", func(t *testing.T) {
		o := run(map[string]string{aliceAK: ed.line + "\n" + rsa.line + "\n# c\n\n" + ec.line + "\n"}, map[string][]string{"alice": {ed.fp, rsa.fp}})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"alice:" + ec.fp}) {
			t.Fatalf("subjects %v", subjects(o))
		}
		if d := o.Evidence[0].Detail; d != "ecdsa-sha2-nistp256 key in .ssh/authorized_keys line 5" {
			t.Fatalf("detail %q", d)
		}
		// the comment line is not a warning
		if strings.Contains(o.Summary, "warning") {
			t.Fatalf("summary %q", o.Summary)
		}
	})
	t.Run("a user without an expected entry has only unexpected keys", func(t *testing.T) {
		o := run(map[string]string{aliceAK: ed.line + "\n", bobAK: rsa.line + "\n"}, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"bob:" + rsa.fp}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("root is examined", func(t *testing.T) {
		o := run(map[string]string{rootAK: ed.line + "\n"}, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"root:" + ed.fp}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("a key that is expected for another user is unexpected here", func(t *testing.T) {
		o := run(map[string]string{bobAK: ed.line + "\n"}, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"bob:" + ed.fp}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("a missing expected key warns", func(t *testing.T) {
		o := run(map[string]string{aliceAK: ed.line + "\n"}, map[string][]string{"alice": {ed.fp, rsa.fp}})
		wantStatus(t, o, result.Warn)
		if !eq(subjects(o), []string{"alice:" + rsa.fp}) || !strings.Contains(o.Evidence[0].Detail, "not found") {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("fail wins and counts the warnings in the summary", func(t *testing.T) {
		o := run(map[string]string{aliceAK: ec.line + "\n"}, map[string][]string{"alice": {rsa.fp}})
		wantStatus(t, o, result.Fail)
		wantSummary(t, o, "also 1 warning(s): alice:"+rsa.fp)
		if len(o.Evidence) != 1 || o.Evidence[0].Subject != "alice:"+ec.fp {
			t.Fatalf("a failing outcome holds failing items only: %+v", o.Evidence)
		}
	})
	t.Run("a trailing = in the configured fingerprint is tolerated", func(t *testing.T) {
		o := run(map[string]string{aliceAK: ed.line + "\n"}, map[string][]string{"alice": {ed.fp + "="}})
		wantStatus(t, o, result.Pass)
	})
	t.Run("the same key in two files counts once", func(t *testing.T) {
		o := run(map[string]string{aliceAK: ed.line + "\n", aliceAK2: ed.line + "\n"}, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "all 1 authorized key(s)")
		o = run(map[string]string{aliceAK: ed.line + "\n", aliceAK2: ed.line + "\n"}, map[string][]string{"alice": {rsa.fp}})
		if len(o.Evidence) != 1 || o.Evidence[0].Subject != "alice:"+ed.fp {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("no key files at all", func(t *testing.T) {
		wantStatus(t, run(nil, map[string][]string{"alice": nil}), result.Pass)
		o := run(nil, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Warn)
	})
	t.Run("an expected user without an account", func(t *testing.T) {
		o := run(map[string]string{aliceAK: ed.line + "\n"}, map[string][]string{"alice": {ed.fp}, "ghost": {rsa.fp}})
		wantStatus(t, o, result.Warn)
		if !eq(subjects(o), []string{"ghost"}) || !strings.Contains(o.Evidence[0].Detail, "no usable account") {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("an expected user whose shell is nologin is examined", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{"/home/svc\x00.ssh/authorized_keys": rsa.line + "\n"})
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"svc": {ed.fp}})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"svc:" + rsa.fp}) {
			t.Fatalf("evidence %+v", o.Evidence)
		}
		// without being named, the same user is not examined
		o = execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Warn)
	})
}

func TestAuthorizedKeysOptionsAndOddLines(t *testing.T) {
	v := "ubuntu2404"
	ed, rsa := loadKey(t, v, "ed25519"), loadKey(t, v, "rsa")
	blob := strings.Fields(ed.line)[1]
	rblob := strings.Fields(rsa.line)[1]
	run := func(content string) probes.Outcome {
		return execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), keyHost(t, v, map[string]string{aliceAK: content}), map[string][]string{"alice": {ed.fp}})
	}
	pass := []string{
		"ssh-ed25519 " + blob,
		"ssh-ed25519 " + blob + " comment",
		"  ssh-ed25519 " + blob + "\r",
		"\tssh-ed25519\t" + blob + "\tcomment",
		`no-pty ssh-ed25519 ` + blob,
		`command="/bin/true",no-pty,no-port-forwarding ssh-ed25519 ` + blob + " c",
		`command="echo hello world" ssh-ed25519 ` + blob,
		`command="echo \"quoted blanks\" x" ssh-ed25519 ` + blob,
		`from="192.0.2.0/24,!192.0.2.128/25",environment="A=b c" ssh-ed25519 ` + blob,
		`cert-authority,principals="a b" ssh-ed25519 ` + blob,
	}
	for _, line := range pass {
		t.Run("ok "+line[:min(len(line), 30)], func(t *testing.T) {
			wantStatus(t, run(line+"\n"), result.Pass)
		})
	}
	t.Run("an option field that looks like a key type is not skipped past", func(t *testing.T) {
		// the options come first and hold a blank inside quotes; the key follows
		wantStatus(t, run(`command="ssh-rsa AAAA foo" ssh-ed25519 `+blob+"\n"), result.Pass)
	})
	// A line that cannot be read is a warning, unless it starts with the name
	// of a key type that sshd reads: sshd may accept a key from it, so it is a
	// fail (the safety net).
	bad := map[string]struct {
		line string
		want result.Status
		why  string
	}{
		"garbage":                           {"this is not a key", result.Warn, "no known key type"},
		"unterminated quote":                {`command="echo ssh-ed25519 ` + blob, result.Warn, "unterminated quote in the options"},
		"option then nothing":               {`no-pty`, result.Warn, "no known key type"},
		"unknown key type":                  {"ssh-foo " + blob, result.Warn, "no known key type"},
		"shadow-like line":                  {"root:$6$abc$def:19000:0:99999:7:::", result.Warn, ""},
		"certificate":                       {strings.Join([]string{"ssh-ed25519-cert-v01@openssh.com", blob}, " "), result.Warn, "no known key type"},
		"type without data":                 {"ssh-ed25519", result.Fail, "no key data"},
		"data not base64":                   {"ssh-ed25519 !!!notbase64!!!", result.Fail, "key data is not valid base64"},
		"data unpadded":                     {"ecdsa-sha2-nistp256 " + strings.TrimRight(strings.Fields(loadKey(t, v, "ecdsa").line)[1], "="), result.Fail, "key data is not valid base64"},
		"blob of another type":              {"ssh-ed25519 " + rblob, result.Fail, "key data is not valid base64"},
		"rsa type, ed25519 blob":            {"ssh-rsa " + blob, result.Fail, "key data is not valid base64"},
		"empty data":                        {"ssh-ed25519 =", result.Fail, ""},
		"blob too large":                    {"ssh-ed25519 " + strings.Repeat("A", 17000), result.Fail, "key data is not valid base64"},
		"nul in the blob":                   {"ssh-ed25519 " + blob[:20] + "\x00" + blob[20:], result.Fail, ""},
		"options, then a type without data": {`no-pty ssh-ed25519`, result.Fail, ""},
	}
	for name, c := range bad {
		t.Run("bad "+name, func(t *testing.T) {
			o := run(ed.line + "\nline two\n" + c.line + "\n")
			wantStatus(t, o, c.want)
			var sub string
			for _, e := range o.Evidence {
				if strings.HasPrefix(e.Subject, "alice:.ssh/authorized_keys:3") {
					sub = e.Detail
				}
				if strings.Contains(e.Detail+e.Subject, "root:$6$") || strings.Contains(e.Detail+e.Subject, "this is not") {
					t.Fatalf("content leaked: %+v", e)
				}
			}
			if sub == "" {
				t.Fatalf("no evidence for line 3: %+v", o.Evidence)
			}
			if c.want == result.Fail && !strings.Contains(sub, "may hold an unchecked key") {
				t.Fatalf("detail %q", sub)
			}
			if c.why != "" && !strings.Contains(sub, c.why) {
				t.Fatalf("reason %q, want it to contain %q", sub, c.why)
			}
		})
	}
	// wantUnreadable: the line is not listed as a key and is a failing item
	wantUnreadable := func(t *testing.T, o probes.Outcome) {
		t.Helper()
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"alice:.ssh/authorized_keys:2"}) || !strings.Contains(o.Evidence[0].Detail, "may hold an unchecked key") {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	}
	// wantListed: the line is a key that is not the expected one
	wantListed := func(t *testing.T, o probes.Outcome) {
		t.Helper()
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 1 || !strings.HasPrefix(o.Evidence[0].Subject, "alice:SHA256:") {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	}
	t.Run("a blob over the size limit is refused whatever its shape", func(t *testing.T) {
		big := base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e", strings.Repeat("n", 17000)))
		small := base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e", strings.Repeat("n", 1000)))
		wantUnreadable(t, run(ed.line+"\nssh-rsa "+big+"\n"))
		wantListed(t, run(ed.line+"\nssh-rsa "+small+"\n"))
	})
	t.Run("the blob must name its own type", func(t *testing.T) {
		line := "ssh-rsa " + base64.StdEncoding.EncodeToString(wire("ssh-foo", "e", "n"))
		wantUnreadable(t, run(ed.line+"\n"+line+"\n"))
	})
	t.Run("a bad line does not hide the keys around it", func(t *testing.T) {
		o := run("garbage\n" + ed.line + "\n" + rsa.line + "\n")
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"alice:" + rsa.fp}) {
			t.Fatalf("evidence %+v", o.Evidence)
		}
		wantSummary(t, o, "also 1 warning(s)")
	})
	t.Run("the shape of a key blob must be the one OpenSSH reads", func(t *testing.T) {
		curve := func(typ, name string) string {
			return typ + " " + base64.StdEncoding.EncodeToString(wire(typ, name, ecPoint(name)))
		}
		for name, line := range map[string]string{
			"ed25519 key of 31 bytes":       "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire("ssh-ed25519", pk32("a")[:31])),
			"ed25519 key of 33 bytes":       "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire("ssh-ed25519", pk32("a")+"x")),
			"ed25519 blob with a field":     "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire("ssh-ed25519", pk32("a"), "more")),
			"ecdsa nistp256, curve p384":    curve("ecdsa-sha2-nistp256", "nistp384"),
			"ecdsa nistp384, curve p256":    curve("ecdsa-sha2-nistp384", "nistp256"),
			"ecdsa curve of another name":   curve("ecdsa-sha2-nistp521", "other"),
			"ecdsa point of the wrong size": "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(wire("ecdsa-sha2-nistp256", "nistp256", ecPoint("nistp384"))),
			"ecdsa compressed point":        "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(wire("ecdsa-sha2-nistp256", "nistp256", "\x02"+strings.Repeat("a", 32))),
			"sk-ecdsa with a wrong curve":   "sk-ecdsa-sha2-nistp256@openssh.com " + base64.StdEncoding.EncodeToString(wire("sk-ecdsa-sha2-nistp256@openssh.com", "nistp384", ecPoint("nistp384"), "app")),
			"sk-ed25519 with a short key":   "sk-ssh-ed25519@openssh.com " + base64.StdEncoding.EncodeToString(wire("sk-ssh-ed25519@openssh.com", "short", "app")),
			"rsa blob with one field":       "ssh-rsa " + base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e")),
			"dss blob with too few fields":  "ssh-dss " + base64.StdEncoding.EncodeToString(wire("ssh-dss", "p", "q", "g")),
		} {
			t.Run(name, func(t *testing.T) { wantUnreadable(t, run(ed.line+"\n"+line+"\n")) })
		}
		// the same shapes, right: ecdsa curves, rsa with e and n, dss with four numbers
		for _, line := range []string{
			curve("ecdsa-sha2-nistp384", "nistp384"),
			curve("ecdsa-sha2-nistp521", "nistp521"),
			"ssh-rsa " + base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e", "n")),
			"ssh-dss " + base64.StdEncoding.EncodeToString(wire("ssh-dss", "p", "q", "g", "y")),
		} {
			wantListed(t, run(ed.line+"\n"+line+"\n"))
		}
	})
	t.Run("the sk key types", func(t *testing.T) {
		for _, typ := range []string{"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"} {
			b := wire(typ, pk32("x"), "application")
			if typ == "sk-ecdsa-sha2-nistp256@openssh.com" {
				b = wire(typ, "nistp256", ecPoint("nistp256"), "application")
			}
			line := typ + " " + base64.StdEncoding.EncodeToString(b)
			sum := sha256.Sum256(b)
			fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			fsys := keyHost(t, v, map[string]string{aliceAK: line + "\n"})
			o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {fp}})
			wantStatus(t, o, result.Pass)
		}
	})
	t.Run("a blob whose length prefix is a lie", func(t *testing.T) {
		b := []byte{0, 0, 1, 0, 'a'}
		line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b)
		wantStatus(t, run(line+"\n"), result.Fail)
		wantStatus(t, run("ssh-ed25519 "+base64.StdEncoding.EncodeToString([]byte{0, 1})+"\n"), result.Fail)
	})
}

// ecPoint is an uncompressed point (0x04, x, y) of the size of the curve.
func ecPoint(curve string) string {
	return "\x04" + strings.Repeat("p", 2*map[string]int{"nistp256": 32, "nistp384": 48, "nistp521": 66}[curve])
}

// pk32 pads s to the 32 bytes of an ed25519 public key.
func pk32(s string) string { return (s + strings.Repeat("_", 32))[:32] }

// wire builds a key blob: the type and further strings in SSH wire format.
func wire(parts ...string) []byte {
	var b []byte
	for _, p := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return b
}

func TestAuthorizedKeysPaths(t *testing.T) {
	v := "ubuntu2404"
	ed, rsa := loadKey(t, v, "ed25519"), loadKey(t, v, "rsa")
	t.Run("custom AuthorizedKeysFile: home paths, absolute paths and tokens", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{
			"/home/alice\x00.ssh/authorized_keys": ed.line + "\n",  // %h/.ssh/authorized_keys, turned into a path in the home
			"/home/alice\x00.ssh/ak_1001":         rsa.line + "\n", // .ssh/ak_%U
		})
		fsys.Files["/etc/ssh/keys/alice"] = rsa.line + "\n" // /etc/ssh/keys/%u, outside the home
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_authkeys_custom"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Fail)
		var subs []string
		for _, e := range o.Evidence {
			subs = append(subs, e.Subject+" "+e.Detail)
		}
		if len(o.Evidence) != 1 || o.Evidence[0].Subject != "alice:"+rsa.fp || !strings.Contains(o.Evidence[0].Detail, "/etc/ssh/keys/alice line 1") {
			t.Fatalf("evidence %v", subs)
		}
	})
	t.Run("AuthorizedKeysCommand is a warning", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{"/home/alice\x00.ssh/authorized_keys": ed.line + "\n"})
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_authkeys_custom"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Warn)
		if !eq(subjects(o), []string{"authorizedkeyscommand"}) || !strings.Contains(o.Evidence[0].Detail, "/usr/local/bin/kwkeys") {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("AuthorizedKeysFile none reads nothing", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{"/home/alice\x00.ssh/authorized_keys": ed.line + "\n", "/home/alice\x00none": rsa.line + "\n"})
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_authkeys_none"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Warn)
		if !eq(subjects(o), []string{"alice:" + ed.fp}) {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("an absolute path outside the home is read as trusted", func(t *testing.T) {
		fsys := keyHost(t, v, nil)
		fsys.Errs = map[string]error{"/etc/ssh/keys/alice": fmt.Errorf("%w: directory /etc/ssh is owned by uid 1000", probes.ErrUnsafe)}
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_authkeys_custom"), fsys, map[string][]string{"alice": nil})
		wantStatus(t, o, result.Warn)
		found := false
		for _, e := range o.Evidence {
			if e.Subject == "alice:/etc/ssh/keys/alice" && strings.Contains(e.Detail, "owned by uid") {
				found = true
			}
		}
		if !found {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
}

// sshdWith returns a runner whose sshd -T prints the given lines.
func sshdWith(lines ...string) *fake.FakeRunner {
	return newRunner().AddResult(sshdArgv, inline(strings.Join(lines, "\n")+"\n", 0))
}

func TestAuthorizedKeysTokenExpansion(t *testing.T) {
	v := "ubuntu2404"
	ed := loadKey(t, v, "ed25519")
	cases := []struct {
		pattern string
		key     string // Homes key that holds the key, "" for none
		trusted string // Files path that holds the key
		warn    string // substring of a warning, "" for none
	}{
		{".ssh/authorized_keys", aliceAK, "", ""},
		{"%h/.ssh/authorized_keys", aliceAK, "", ""},
		{"./.ssh/../.ssh/authorized_keys", aliceAK, "", ""},
		{"%%h", "", "", ""}, // a file called %h in the home: nothing there
		{"keys/%u/%U", "/home/alice\x00keys/alice/1001", "", ""},
		{"/home/alice/.ssh/authorized_keys", aliceAK, "", ""},
		{"/home/alice/../alice/.ssh/authorized_keys", aliceAK, "", ""},
		{"/srv/keys/%u", "", "/srv/keys/alice", ""},
		{"/home/alicex/keys", "", "/home/alicex/keys", ""}, // a sibling directory, not the home
		{"/srv/%%/%u", "", "/srv/%/alice", ""},
		{"%x/keys", "", "", "token %x"},
		{"keys/%", "", "", "lone %"},
		{"../bob/.ssh/authorized_keys", "", "", "leaves the home"},
		{"..", "", "", "leaves the home"},
		{".", "", "", "leaves the home"},
	}
	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			fsys := keyHost(t, v, nil)
			fsys.Files["/etc/passwd"] = "alice:x:1001:1001::/home/alice:/bin/bash\n"
			if c.key != "" {
				fsys.Homes[c.key] = ed.line + "\n"
			}
			if c.trusted != "" {
				fsys.Files[c.trusted] = ed.line + "\n"
			}
			o := execKeys(keysProbe(t), sshdWith("authorizedkeysfile "+c.pattern, "authorizedkeyscommand none"), fsys, map[string][]string{"alice": {ed.fp}})
			if c.warn != "" {
				wantStatus(t, o, result.Warn)
				if !strings.Contains(allText(o), c.warn) {
					t.Fatalf("evidence %+v", o.Evidence)
				}
				return
			}
			if c.key != "" || c.trusted != "" {
				wantStatus(t, o, result.Pass)
			} else {
				wantStatus(t, o, result.Warn) // the expected key is not found
			}
		})
	}
	t.Run("home is the root directory", func(t *testing.T) {
		fsys := probestest.FakeFS{
			Files: map[string]string{"/etc/passwd": "alice:x:1001:1001::/:/bin/sh\n", "/etc/keys/alice": ed.line + "\n"},
			Homes: map[string]string{"/\x00.ssh/authorized_keys": ed.line + "\n"},
		}
		o := execKeys(keysProbe(t), sshdWith("authorizedkeysfile .ssh/authorized_keys /etc/keys/%u", "authorizedkeyscommand none"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Pass)
	})
}

func TestAuthorizedKeysReadProblemsAreWarnings(t *testing.T) {
	v := "ubuntu2404"
	ed := loadKey(t, v, "ed25519")
	for name, err := range map[string]error{
		"too large":     probes.ErrTooLarge,
		"unsafe":        fmt.Errorf("%w: .ssh/authorized_keys is owned by uid 5", probes.ErrUnsafe),
		"escape":        errors.New("openat .ssh/authorized_keys: path escapes from parent"),
		"permission":    fs.ErrPermission,
		"io":            errors.New("input/output error"),
		"wrapped":       fmt.Errorf("open: %w", errors.New("too many levels of symbolic links")),
		"multiline err": errors.New("boom\nroot:x:0:0::/root:/bin/bash\x1b[0m"),
	} {
		t.Run(name, func(t *testing.T) {
			fsys := keyHost(t, v, map[string]string{})
			fsys.Errs = map[string]error{aliceAK: err}
			o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {ed.fp}})
			wantStatus(t, o, result.Warn)
			var found bool
			for _, e := range o.Evidence {
				if strings.ContainsAny(e.Subject+e.Detail, "\n\x1b") {
					t.Fatalf("control character in %+v", e)
				}
				if e.Subject == "alice:.ssh/authorized_keys" && strings.HasPrefix(e.Detail, "not read: ") {
					found = true
				}
			}
			if !found {
				t.Fatalf("evidence %+v", o.Evidence)
			}
		})
	}
	t.Run("the reasons are readable", func(t *testing.T) {
		for err, want := range map[error]string{
			probes.ErrTooLarge: "larger than 256 KiB",
			errors.New("openat x: path escapes from parent"): "leads out of the home directory",
		} {
			fsys := keyHost(t, v, nil)
			fsys.Errs = map[string]error{aliceAK: err}
			o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {ed.fp}})
			if !strings.Contains(allText(o), want) {
				t.Errorf("%q lacks %q", allText(o), want)
			}
		}
	})
	t.Run("a user making the file unreadable does not turn a failure into a pass", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{aliceAK: ed.line + "\n"})
		fsys.Errs = map[string]error{aliceAK2: errors.New("path escapes from parent")}
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Warn)
	})
	t.Run("a file system without the operations is an error", func(t *testing.T) {
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), probestest.MemFS{"/etc/passwd": fixtureFile(t, v+"/etc_passwd.stdout")}, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "does not offer")
	})
}

func TestAuthorizedKeysAccounts(t *testing.T) {
	v := "ubuntu2404"
	ed := loadKey(t, v, "ed25519")
	passwd := strings.Join([]string{
		"# a comment",
		"+@netgroup:::::::",
		"-baduser",
		"root:x:0:0:root:/root:/bin/bash",
		"sys:x:3:3:sys:/dev:/bin/sh",
		"low:x:999:999::/home/low:/bin/bash",
		"edge:x:1000:1000::/home/edge:/bin/bash",
		"locked:x:1001:1001::/home/locked:/usr/sbin/nologin",
		"locked2:x:1002:1002::/home/locked2:/bin/false",
		"locked3:x:1004:1004::/home/locked3:/sbin/nologin",
		"locked4:x:1005:1005::/home/locked4:/usr/bin/false",
		"empty:x:1003:1003::/home/empty:",
		"dup:x:1006:1006::/home/dup:/bin/sh",
		"dup:x:1007:1007::/home/dup2:/bin/sh",
		"",
	}, "\n")
	fsys := probestest.FakeFS{Files: map[string]string{"/etc/passwd": passwd}, Homes: map[string]string{}}
	for _, u := range []string{"root", "sys", "low", "edge", "locked", "locked2", "locked3", "locked4", "empty", "dup"} {
		home := "/home/" + u
		if u == "root" {
			home = "/root"
		}
		fsys.Homes[probestest.HomeKey(home, ".ssh/authorized_keys")] = ed.line + "\n"
	}
	o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"someone": {ed.fp}})
	wantStatus(t, o, result.Fail)
	got := map[string]bool{}
	for _, e := range o.Evidence {
		got[strings.SplitN(e.Subject, ":", 2)[0]] = true
	}
	for _, u := range []string{"root", "edge", "empty", "dup"} {
		if !got[u] {
			t.Errorf("%s was not examined: %v", u, subjects(o))
		}
	}
	for _, u := range []string{"sys", "low", "locked", "locked2", "locked3", "locked4"} {
		if got[u] {
			t.Errorf("%s was examined: %v", u, subjects(o))
		}
	}
	if len(o.Evidence) != 4 {
		t.Fatalf("evidence %v", subjects(o))
	}
	if !strings.Contains(o.Summary, "also 1 warning(s): someone") {
		t.Fatalf("summary %q", o.Summary)
	}

	t.Run("lines that cannot be read are warnings", func(t *testing.T) {
		bad := "root:x:0:0:root:/root:/bin/bash\nshort:x:1010\nbad name:x:1011:1011::/home/x:/bin/sh\nrel:x:1012:1012::home/rel:/bin/sh\nuid:x:abc:1::/home/u:/bin/sh\nneg:x:-1:1::/home/u:/bin/sh\nbig:x:99999999999:1::/home/u:/bin/sh\n"
		fsys := probestest.FakeFS{Files: map[string]string{"/etc/passwd": bad}}
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"root": {ed.fp}})
		wantStatus(t, o, result.Warn)
		var passwdWarns int
		for _, e := range o.Evidence {
			if strings.HasPrefix(e.Subject, "passwd:") {
				passwdWarns++
			}
		}
		if passwdWarns != 6 {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("a line with a field too many is not read as an account", func(t *testing.T) {
		// 8 fields: the home and shell cannot be told, so the user is not examined and the line is a warning
		fsys := probestest.FakeFS{
			Files: map[string]string{"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\neight:x:1013:1013::/home/eight:/bin/sh:extra\n"},
			Homes: map[string]string{probestest.HomeKey("/home/eight", ".ssh/authorized_keys"): ed.line + "\n"},
		}
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"root": nil})
		wantStatus(t, o, result.Warn)
		if !eq(subjects(o), []string{"passwd:2"}) {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("passwd that cannot be read", func(t *testing.T) {
		for _, fsys := range []probestest.FakeFS{{}, {Errs: map[string]error{"/etc/passwd": fs.ErrPermission}}, {Files: map[string]string{"/etc/passwd": strings.Repeat("x", 5<<20)}}} {
			o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"root": {ed.fp}})
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "/etc/passwd")
		}
	})
	t.Run("user names that cannot be put into a path", func(t *testing.T) {
		fsys := probestest.FakeFS{Files: map[string]string{"/etc/passwd": "../../x:x:1500:1500::/home/x:/bin/sh\nx/y:x:1501:1501::/home/y:/bin/sh\n"}}
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"root": nil})
		wantStatus(t, o, result.Warn)
		for _, e := range o.Evidence {
			if strings.Contains(e.Subject, "..") || strings.Contains(e.Subject, "x/y") {
				t.Fatalf("unusable name in %+v", e)
			}
		}
	})
}

func TestAuthorizedKeysSshdProblems(t *testing.T) {
	v := "ubuntu2404"
	ed, rsa := loadKey(t, v, "ed25519"), loadKey(t, v, "rsa")
	fsys := func() probestest.FakeFS {
		return keyHost(t, v, map[string]string{aliceAK: ed.line + "\n" + rsa.line + "\n"})
	}
	exp := map[string][]string{"alice": {ed.fp}}
	t.Run("sshd is not installed", func(t *testing.T) {
		wantStatus(t, execKeys(keysProbe(t), newRunner().AddError(sshdArgv, execx.ErrNotFound), fsys(), exp), result.Skipped)
	})
	t.Run("sshd -T fails: default paths, findings kept, status error", func(t *testing.T) {
		for _, r := range []*fake.FakeRunner{
			newRunner().Add(sshdArgv, v+"/sshd_T_no_privsep_dir"),
			newRunner().AddError(sshdArgv, execx.ErrTimeout),
			newRunner().AddResult(sshdArgv, execx.Result{Stdout: []byte("authorizedkeysfile none\n"), Truncated: true}),
			newRunner().AddResult(sshdArgv, inline("garbage line here\n", 0)),
			newRunner().AddResult(sshdArgv, inline("", 0)),
			sshdWith("authorizedkeysfile a", "authorizedkeysfile b"),
			sshdWith("authorizedkeysfile .ssh/authorized_keys", "authorizedkeyscommand none", "authorizedkeyscommand x"),
			sshdWith("port 22"),
			sshdWith("authorizedkeysfile .ssh/authorized_keys"),
			sshdWith("authorizedkeyscommand none"),
		} {
			o := execKeys(keysProbe(t), r, fsys(), exp)
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "default paths were used")
			if !eq(subjects(o), []string{"alice:" + rsa.fp}) {
				t.Fatalf("a confirmed finding must stay: %+v (%s)", o.Evidence, o.Summary)
			}
		}
	})
	t.Run("sshd -T fails and nothing is wrong in the default files", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{aliceAK: ed.line + "\n"})
		o := execKeys(keysProbe(t), newRunner().Add(sshdArgv, v+"/sshd_T_no_privsep_dir"), fsys, exp)
		wantStatus(t, o, result.Error)
		if len(o.Evidence) != 0 {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("sshd -T that is missing a mandatory option is not trusted, nor is a repeated one", func(t *testing.T) {
		// the "sshd_T_default" fixture has both; take them out
		out := strings.ReplaceAll(fixtureFile(t, v+"/sshd_T_default.stdout"), "authorizedkeyscommand none\n", "")
		wantStatus(t, execKeys(keysProbe(t), newRunner().AddResult(sshdArgv, inline(out, 0)), fsys(), exp), result.Error)
	})
	t.Run("no expected keys configured", func(t *testing.T) {
		for _, e := range []map[string][]string{nil, {}} {
			o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys(), e)
			wantStatus(t, o, result.Skipped)
			wantSummary(t, o, "authorized_keys.expected")
		}
		// a user with an empty list still counts as configured
		wantStatus(t, execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys(), map[string][]string{"alice": nil}), result.Fail)
	})
	t.Run("a nonzero status is not trusted", func(t *testing.T) {
		r := newRunner().AddResult(sshdArgv, execx.Result{Stdout: []byte("authorizedkeysfile .ssh/authorized_keys\n"), ExitCode: 255})
		wantStatus(t, execKeys(keysProbe(t), r, fsys(), exp), result.Error)
	})
	t.Run("sshd -T output keeps the case of paths", func(t *testing.T) {
		fs := keyHost(t, v, nil)
		fs.Files["/etc/passwd"] = "alice:x:1001:1001::/home/alice:/bin/bash\n"
		fs.Files["/Srv/Keys"] = ed.line + "\n"
		o := execKeys(keysProbe(t), sshdWith("authorizedkeysfile /Srv/Keys", "authorizedkeyscommand none"), fs, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Pass)
	})
	t.Run("the shared sshd -T run is the same argv as sshd_effective", func(t *testing.T) {
		r := sshdFixture(v, "sshd_T_default")
		execKeys(keysProbe(t), r, fsys(), exp)
		if c := r.Calls(); len(c) != 1 || strings.Join(c[0].Argv, " ") != "sshd -T" {
			t.Fatalf("calls %+v", c)
		}
	})
	commonFailures(t, withKeys{keysProbe(t), exp}, sshdArgv, "sshd", fsys())
}

// withKeys configures the expected keys of the probe's environment.
type withKeys struct {
	probes.Probe
	expected map[string][]string
}

func (w withKeys) Run(ctx context.Context, env *probes.Env) probes.Outcome {
	env.AuthorizedKeys = w.expected
	return w.Probe.Run(ctx, env)
}

func TestAuthorizedKeysEvidenceIsLimited(t *testing.T) {
	v := "ubuntu2404"
	ed := loadKey(t, v, "ed25519")
	t.Run("many unexpected keys", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 150; i++ {
			k := wire("ssh-ed25519", pk32(fmt.Sprintf("key%03d", i)))
			b.WriteString("ssh-ed25519 " + base64.StdEncoding.EncodeToString(k) + "\n")
		}
		fsys := keyHost(t, v, map[string]string{aliceAK: b.String()})
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 100 || !strings.HasSuffix(o.Evidence[99].Subject, "more not shown)") {
			t.Fatalf("%d items, last %+v", len(o.Evidence), o.Evidence[len(o.Evidence)-1])
		}
		wantSummary(t, o, "and 51 more")
	})
	t.Run("many garbage lines", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{aliceAK: strings.Repeat("garbage\n", 5000) + ed.line + "\n"})
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Warn)
		if len(o.Evidence) != 100 {
			t.Fatalf("%d items", len(o.Evidence))
		}
	})
	t.Run("garbage in one account does not hide an unexpected key in another", func(t *testing.T) {
		fsys := keyHost(t, v, map[string]string{aliceAK: strings.Repeat("garbage\n", 5000), bobAK: ed.line + "\n"})
		o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {ed.fp}})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"bob:" + ed.fp}) {
			t.Fatalf("evidence %v", subjects(o))
		}
	})
}

func TestAuthorizedKeysPrepareTakesNoParameters(t *testing.T) {
	prepareErr(t, "authorized_keys", map[string]any{"x": 1})
}

// ---- key types, integers and whitespace as sshd reads them (F2, F3)

// blobOf returns the decoded blob of a public key line.
func blobOf(t *testing.T, line string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.Fields(line)[1])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// splitWire reads the strings of a wire format blob.
func splitWire(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var f [][]byte
	for len(b) > 0 {
		n := binary.BigEndian.Uint32(b)
		f = append(f, b[4:4+n])
		b = b[4+n:]
	}
	return f
}

func joinWire(fields ...[]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

func fpOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// keyLineOutcome runs the probe on a file with the expected key of ed and the
// given extra line (the user alice expects only ed25519 key ed).
func keyLineOutcome(t *testing.T, v string, expect []string, lines ...string) probes.Outcome {
	t.Helper()
	fsys := keyHost(t, v, map[string]string{aliceAK: strings.Join(lines, "\n") + "\n"})
	return execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": expect})
}

// listedKey: the one extra line is a key with this fingerprint, expected or not.
func wantKeyFP(t *testing.T, v, what, line, fp string) {
	t.Helper()
	o := keyLineOutcome(t, v, []string{fp}, line)
	if o.Status != result.Pass {
		t.Errorf("%s: %s (%s): %+v", what, o.Status, o.Summary, o.Evidence)
	}
}

func wantNotAKey(t *testing.T, v, what, line string, want result.Status) {
	t.Helper()
	ed := loadKey(t, v, "ed25519")
	o := keyLineOutcome(t, v, []string{ed.fp}, ed.line, line)
	if o.Status != want {
		t.Errorf("%s: %s (%s), want %s: %+v", what, o.Status, o.Summary, want, o.Evidence)
		return
	}
	for _, e := range o.Evidence {
		if strings.HasPrefix(e.Subject, "alice:SHA256:") {
			t.Errorf("%s: listed as the key %s", what, e.Subject)
		}
	}
}

// The key type names that sshd reads at the start of a key (the table of key
// types of OpenSSH 8.9 and 9.6; sshkey_read compares the whole word exactly,
// case sensitive) and the ones it does not.
func TestAuthorizedKeysKeyTypeNames(t *testing.T) {
	for _, v := range versions {
		ed, rs, ec := loadKey(t, v, "ed25519"), loadKey(t, v, "rsa"), loadKey(t, v, "ecdsa")
		edb, rsb, ecb := strings.Fields(ed.line)[1], strings.Fields(rs.line)[1], strings.Fields(ec.line)[1]
		sk := joinWire([]byte("sk-ecdsa-sha2-nistp256@openssh.com"), []byte("nistp256"), []byte(ecPoint("nistp256")), []byte("ssh:"))
		sked := joinWire([]byte("sk-ssh-ed25519@openssh.com"), []byte(pk32("k")), []byte("ssh:"))
		for _, c := range []struct{ name, blob, fp string }{
			{"ssh-ed25519", edb, ed.fp},
			{"ssh-rsa", rsb, rs.fp},
			{"rsa-sha2-256", rsb, rs.fp},
			{"rsa-sha2-512", rsb, rs.fp},
			{"ecdsa-sha2-nistp256", ecb, ec.fp},
			{"sk-ecdsa-sha2-nistp256@openssh.com", base64.StdEncoding.EncodeToString(sk), fpOf(sk)},
			{"webauthn-sk-ecdsa-sha2-nistp256@openssh.com", base64.StdEncoding.EncodeToString(sk), fpOf(sk)},
			{"sk-ssh-ed25519@openssh.com", base64.StdEncoding.EncodeToString(sked), fpOf(sked)},
		} {
			wantKeyFP(t, v, v+" "+c.name, c.name+" "+c.blob+" comment", c.fp)
		}
		for _, name := range []string{
			"ED25519", "Ed25519", "SSH-ED25519", "Ssh-ed25519", "ssh-Ed25519", "RSA", "rsa", "ECDSA", "ED25519-SK", "DSA",
			"rsa-sha2-384", "RSA-SHA2-256", "ssh-ed448", "ssh-xmss@openssh.com", "sk-ssh-ed25519", "webauthn-sk-ecdsa-sha2-nistp256",
			"ssh-ed25519-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
			"sk-ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
		} {
			wantNotAKey(t, v, v+" "+name, name+" "+rsb+" x", result.Warn)
			wantNotAKey(t, v, v+" "+name+" with an ed25519 blob", name+" "+edb+" x", result.Warn)
		}
	}
}

// OpenSSH computes the fingerprint of the key it parsed, written back in its
// canonical form, and not of the text it read.
func TestAuthorizedKeysCanonicalIntegers(t *testing.T) {
	for _, v := range versions {
		rs := loadKey(t, v, "rsa")
		f := splitWire(t, blobOf(t, rs.line))
		typ, e, n := f[0], f[1], f[2]
		if n[0] != 0 || n[1]&0x80 == 0 {
			t.Fatalf("%s: the fixture key has an unexpected modulus", v)
		}
		z := func(k int) []byte { return make([]byte, k) }
		line := func(fields ...[]byte) string {
			return "ssh-rsa " + base64.StdEncoding.EncodeToString(joinWire(fields...))
		}
		wantKeyFP(t, v, "canonical", line(typ, e, n), rs.fp)
		wantKeyFP(t, v, "one zero byte in front of e", line(typ, append(z(1), e...), n), rs.fp)
		wantKeyFP(t, v, "five zero bytes in front of e, three in front of n", line(typ, append(z(5), e...), append(z(3), n...)), rs.fp)
		wantKeyFP(t, v, "e of zero bytes only before the value", line(typ, append(z(40), e...), n), rs.fp)
		// a modulus that fills 2048 bytes behind a zero byte is still read; the
		// fingerprint is of the integer, so it differs from the key's
		big := append([]byte{0x7f}, z(2047)...)
		wantKeyFP(t, v, "a modulus of 2048 bytes", line(typ, e, big), fpOf(joinWire(typ, e, big)))
		wantKeyFP(t, v, "a modulus of 2048 bytes behind a zero byte", line(typ, e, append(z(1), append([]byte{0x80}, z(2047)...)...)), fpOf(joinWire(typ, e, append(z(1), append([]byte{0x80}, z(2047)...)...))))
		// refused by OpenSSH: negative integers and integers over 2048 bytes
		unreadable := func(what, l string) {
			ed := loadKey(t, v, "ed25519")
			o := keyLineOutcome(t, v, []string{ed.fp}, ed.line, l)
			if o.Status != result.Fail || len(o.Evidence) != 1 || !strings.Contains(o.Evidence[0].Detail, "may hold an unchecked key") {
				t.Errorf("%s %s: %s %+v", v, what, o.Status, o.Evidence)
			}
		}
		unreadable("a negative modulus", line(typ, e, n[1:]))
		unreadable("a negative e", line(typ, []byte{0x80, 1}, n))
		unreadable("a modulus of 2049 bytes", line(typ, e, append([]byte{1}, z(2048)...)))
		unreadable("a modulus of 2050 bytes", line(typ, e, append(z(1), append([]byte{1}, z(2048)...)...)))
		// the same for DSA: four integers, each canonicalised
		d := [][]byte{{0x80, 1}, {0x7f}, {0x9e, 2}, {3}}
		canon := joinWire([]byte("ssh-dss"), append(z(1), d[0]...), d[1], append(z(1), d[2]...), d[3])
		padded := joinWire([]byte("ssh-dss"), append(z(4), append(z(1), d[0]...)...), append(z(2), d[1]...), append(z(3), append(z(1), d[2]...)...), d[3])
		wantKeyFP(t, v, "dss with padded integers", "ssh-dss "+base64.StdEncoding.EncodeToString(padded), fpOf(canon))
		unreadable("a negative dss integer", "ssh-dss "+base64.StdEncoding.EncodeToString(joinWire([]byte("ssh-dss"), d[0], d[1], d[2], d[3])))
	}
}

// The type string at the start of a blob goes through sshkey_type_from_name,
// which knows every name of the type and the short names in any case; for
// ECDSA the name must be exact.
func TestAuthorizedKeysTypeStringInTheBlob(t *testing.T) {
	for _, v := range versions {
		rs, ed, ec := loadKey(t, v, "rsa"), loadKey(t, v, "ed25519"), loadKey(t, v, "ecdsa")
		rf, ef, cf := splitWire(t, blobOf(t, rs.line)), splitWire(t, blobOf(t, ed.line)), splitWire(t, blobOf(t, ec.line))
		with := func(f [][]byte, name string) string {
			return base64.StdEncoding.EncodeToString(joinWire(append([][]byte{[]byte(name)}, f[1:]...)...))
		}
		for _, name := range []string{"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", "RSA", "rsa", "Rsa"} {
			wantKeyFP(t, v, "ssh-rsa line, blob type "+name, "ssh-rsa "+with(rf, name), rs.fp)
			wantKeyFP(t, v, "rsa-sha2-512 line, blob type "+name, "rsa-sha2-512 "+with(rf, name), rs.fp)
		}
		for _, name := range []string{"ssh-ed25519", "ED25519", "ed25519", "Ed25519"} {
			wantKeyFP(t, v, "ssh-ed25519 line, blob type "+name, "ssh-ed25519 "+with(ef, name), ed.fp)
		}
		unreadable := func(what, l string) {
			o := keyLineOutcome(t, v, []string{ed.fp}, ed.line, l)
			if o.Status != result.Fail || len(o.Evidence) != 1 || !strings.Contains(o.Evidence[0].Detail, "may hold an unchecked key") {
				t.Errorf("%s %s: %s %+v", v, what, o.Status, o.Evidence)
			}
		}
		for _, name := range []string{"ssh-ed25519", "ssh-dss", "DSA", "ssh-rsa-cert-v01@openssh.com", "rsa-sha2-384", "ssh-rsa ", ""} {
			unreadable("ssh-rsa line, blob type "+name, "ssh-rsa "+with(rf, name))
		}
		for _, name := range []string{"ssh-rsa", "ED", "ssh-ed25519 ", "ED25519-SK", "ssh-ed25519-cert-v01@openssh.com"} {
			unreadable("ssh-ed25519 line, blob type "+name, "ssh-ed25519 "+with(ef, name))
		}
		wantKeyFP(t, v, "ecdsa, exact name", "ecdsa-sha2-nistp256 "+with(cf, "ecdsa-sha2-nistp256"), ec.fp)
		for _, name := range []string{"ECDSA", "ecdsa", "ecdsa-sha2-nistp384", "nistp256", "ECDSA-SK"} {
			unreadable("ecdsa line, blob type "+name, "ecdsa-sha2-nistp256 "+with(cf, name))
		}
		// sk-ecdsa: the two names of the type; the short name is not accepted
		sk := func(name string) string {
			return base64.StdEncoding.EncodeToString(joinWire([]byte(name), []byte("nistp256"), []byte(ecPoint("nistp256")), []byte("ssh:")))
		}
		canon := joinWire([]byte("sk-ecdsa-sha2-nistp256@openssh.com"), []byte("nistp256"), []byte(ecPoint("nistp256")), []byte("ssh:"))
		wantKeyFP(t, v, "sk-ecdsa", "sk-ecdsa-sha2-nistp256@openssh.com "+sk("sk-ecdsa-sha2-nistp256@openssh.com"), fpOf(canon))
		wantKeyFP(t, v, "sk-ecdsa, webauthn blob type", "sk-ecdsa-sha2-nistp256@openssh.com "+sk("webauthn-sk-ecdsa-sha2-nistp256@openssh.com"), fpOf(canon))
		wantKeyFP(t, v, "webauthn line, sk-ecdsa blob type", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com "+sk("sk-ecdsa-sha2-nistp256@openssh.com"), fpOf(canon))
		unreadable("sk-ecdsa, short blob type", "sk-ecdsa-sha2-nistp256@openssh.com "+sk("ECDSA-SK"))
		skEd := joinWire([]byte("sk-ssh-ed25519@openssh.com"), []byte(pk32("k")), []byte("ssh:"))
		skEdShort := joinWire([]byte("Ed25519-SK"), []byte(pk32("k")), []byte("ssh:"))
		wantKeyFP(t, v, "sk-ed25519, short blob type", "sk-ssh-ed25519@openssh.com "+base64.StdEncoding.EncodeToString(skEdShort), fpOf(skEd))
	}
}

// b64_pton skips every isspace byte anywhere in the text, including around the
// padding, and refuses anything else it cannot decode.
func TestAuthorizedKeysBase64LikeB64Pton(t *testing.T) {
	for _, v := range versions {
		ed, ec := loadKey(t, v, "ed25519"), loadKey(t, v, "ecdsa")
		eb, cb := strings.Fields(ed.line)[1], strings.Fields(ec.line)[1]
		if !strings.HasSuffix(cb, "=") || strings.HasSuffix(cb, "==") {
			t.Fatalf("%s: the ecdsa fixture has no single padding byte", v)
		}
		for _, sp := range []string{"\v", "\f", "\r", "\v\f\r", "\v\v"} {
			wantKeyFP(t, v, "blank inside the text", "ssh-ed25519 "+eb[:20]+sp+eb[20:], ed.fp)
			wantKeyFP(t, v, "blank at the start", "ssh-ed25519 "+sp+eb, ed.fp)
			wantKeyFP(t, v, "blank at the end", "ssh-ed25519 "+eb+sp+" comment", ed.fp)
			wantKeyFP(t, v, "blank in front of the padding", "ecdsa-sha2-nistp256 "+strings.TrimSuffix(cb, "=")+sp+"=", ec.fp)
		}
		wantKeyFP(t, v, "blank in the text of a padded key", "ecdsa-sha2-nistp256 "+cb[:10]+"\v"+cb[10:], ec.fp)
		// not decodable: refused as sshd refuses it
		unreadable := func(what, l string) {
			o := keyLineOutcome(t, v, []string{ed.fp}, ed.line, l)
			if o.Status != result.Fail || len(o.Evidence) != 1 || !strings.Contains(o.Evidence[0].Detail, "may hold an unchecked key") {
				t.Errorf("%s %s: %s %+v", v, what, o.Status, o.Evidence)
			}
		}
		unreadable("a blank after the padding and more text", "ecdsa-sha2-nistp256 "+cb+"\vAAAA")
		unreadable("unpadded", "ecdsa-sha2-nistp256 "+strings.TrimSuffix(cb, "="))
		unreadable("a stray character", "ssh-ed25519 "+eb[:20]+"!"+eb[20:])
		unreadable("a space-like non-ASCII character", "ssh-ed25519 "+eb[:20]+" "+eb[20:])
		unreadable("padding bits set", "ecdsa-sha2-nistp256 "+cb[:len(cb)-2]+"B=")
		// the separator between the type and the text is a blank or a tab only
		wantNotAKey(t, v, "vertical tab after the type", "ssh-ed25519\v"+eb, result.Warn)
		wantNotAKey(t, v, "carriage return before the type", "\rssh-ed25519 "+eb, result.Warn)
	}
}

// A line that cannot be read but starts with a key type that sshd reads is a
// failing item, not a harmless one; any other unreadable line is a warning.
func TestAuthorizedKeysUnreadableKeyLinesFail(t *testing.T) {
	v := "ubuntu2404"
	ed := loadKey(t, v, "ed25519")
	eb := strings.Fields(ed.line)[1]
	fail := map[string]string{
		"key type and a bad blob":                  "ssh-ed25519 AAAA",
		"every key type name":                      "ecdsa-sha2-nistp521 AAAA",
		"webauthn type with a bad blob":            "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAA",
		"key type and nothing":                     "ssh-rsa",
		"key type and blanks":                      "ssh-rsa   ",
		"after options":                            `no-pty ssh-ed25519 AAAA`,
		"after options with quoted blanks":         `command="a b c",from="x y" rsa-sha2-256 AAAA`,
		"after options, tabs":                      "no-pty\tssh-dss\tAAAA",
		"the word after the first word":            "host ssh-ed25519 AAAA",
		"a good key in the comment does not count": "ssh-ed25519 AAAA ssh-ed25519 " + eb,
	}
	for name, line := range fail {
		t.Run("fail "+name, func(t *testing.T) {
			o := keyLineOutcome(t, v, []string{ed.fp}, ed.line, line)
			if o.Status != result.Fail || !eq(subjects(o), []string{"alice:.ssh/authorized_keys:2"}) {
				t.Fatalf("%s %+v", o.Status, o.Evidence)
			}
			wantSummary(t, o, "1 unexpected authorized key(s) (1 of them lines that start with a key type but cannot be read)")
			if strings.Contains(allText(o), "AAAA") {
				t.Fatalf("the line is quoted: %+v", o.Evidence)
			}
		})
	}
	warn := map[string]string{
		"no key type at all":                 "AAAA",
		"options only":                       `command="ssh-ed25519 AAAA"`,
		"a key type inside quotes":           `command="x ssh-ed25519 AAAA" no-pty`,
		"a key type that is no key type":     "ssh-ed25519x AAAA",
		"the key type after two words":       "a b ssh-ed25519 AAAA",
		"an unterminated quote":              `command="x ssh-ed25519 ` + eb,
		"a lone quote in the first word":     `"x ssh-ed25519 AAAA`,
		"a certificate type":                 "ssh-ed25519-cert-v01@openssh.com AAAA",
		"a short key type after options":     "no-pty ED25519 " + eb,
		"a key type after a carriage return": "\rssh-ed25519 " + eb,
	}
	for name, line := range warn {
		t.Run("warn "+name, func(t *testing.T) {
			o := keyLineOutcome(t, v, []string{ed.fp}, ed.line, line)
			if o.Status != result.Warn {
				t.Fatalf("%s %+v", o.Status, o.Evidence)
			}
		})
	}
	t.Run("a readable line with a key after options is not unreadable", func(t *testing.T) {
		wantKeyFP(t, v, "options", `no-pty ssh-ed25519 `+eb, ed.fp)
	})
	t.Run("an unreadable line is listed beside the keys, and is excepted by its subject", func(t *testing.T) {
		o := keyLineOutcome(t, v, []string{ed.fp}, "ssh-ed25519 AAAA", ed.line)
		if o.Status != result.Fail || !eq(subjects(o), []string{"alice:.ssh/authorized_keys:1"}) {
			t.Fatalf("%s %+v", o.Status, o.Evidence)
		}
	})
}
