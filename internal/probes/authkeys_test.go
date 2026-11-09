package probes_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
	bad := map[string]string{
		"garbage":                "this is not a key",
		"unterminated quote":     `command="echo ssh-ed25519 ` + blob,
		"option then nothing":    `no-pty`,
		"unknown key type":       "ssh-foo " + blob,
		"type without data":      "ssh-ed25519",
		"data not base64":        "ssh-ed25519 !!!notbase64!!!",
		"data unpadded":          "ecdsa-sha2-nistp256 " + strings.TrimRight(strings.Fields(loadKey(t, v, "ecdsa").line)[1], "="),
		"blob of another type":   "ssh-ed25519 " + rblob,
		"rsa type, ed25519 blob": "ssh-rsa " + blob,
		"empty data":             "ssh-ed25519 =",
		"shadow-like line":       "root:$6$abc$def:19000:0:99999:7:::",
		"certificate":            strings.Join([]string{"ssh-ed25519-cert-v01@openssh.com", blob}, " "),
		"blob too large":         "ssh-ed25519 " + strings.Repeat("A", 17000),
		"nul in the blob":        "ssh-ed25519 " + blob[:20] + "\x00" + blob[20:],
	}
	for name, line := range bad {
		t.Run("bad "+name, func(t *testing.T) {
			o := run(ed.line + "\nline two\n" + line + "\n")
			wantStatus(t, o, result.Warn)
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
				t.Fatalf("no warning for line 3: %+v", o.Evidence)
			}
			// the reason is one of a fixed set
			reason := map[string]string{
				"garbage":                "no known key type",
				"unknown key type":       "no known key type",
				"option then nothing":    "no known key type",
				"unterminated quote":     "unterminated quote in the options",
				"type without data":      "no key data",
				"data not base64":        "key data is not valid base64",
				"blob of another type":   "key data is not valid base64",
				"blob too large":         "key data is not valid base64",
				"rsa type, ed25519 blob": "key data is not valid base64",
			}[name]
			if reason != "" && !strings.Contains(sub, reason) {
				t.Fatalf("reason %q, want it to contain %q", sub, reason)
			}
		})
	}
	t.Run("a blob over the size limit is refused whatever its shape", func(t *testing.T) {
		big := base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e", strings.Repeat("n", 17000)))
		small := base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e", strings.Repeat("n", 1000)))
		wantStatus(t, run(ed.line+"\nssh-rsa "+big+"\n"), result.Warn)
		wantStatus(t, run(ed.line+"\nssh-rsa "+small+"\n"), result.Fail)
	})
	t.Run("the blob must name its own type", func(t *testing.T) {
		line := "ssh-rsa " + base64.StdEncoding.EncodeToString(wire("ssh-foo", "e", "n"))
		wantStatus(t, run(ed.line+"\n"+line+"\n"), result.Warn)
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
			return typ + " " + base64.StdEncoding.EncodeToString(wire(typ, name, "point"))
		}
		for name, line := range map[string]string{
			"ed25519 key of 31 bytes":      "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire("ssh-ed25519", pk32("a")[:31])),
			"ed25519 key of 33 bytes":      "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire("ssh-ed25519", pk32("a")+"x")),
			"ed25519 blob with a field":    "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire("ssh-ed25519", pk32("a"), "more")),
			"ecdsa nistp256, curve p384":   curve("ecdsa-sha2-nistp256", "nistp384"),
			"ecdsa nistp384, curve p256":   curve("ecdsa-sha2-nistp384", "nistp256"),
			"ecdsa curve of another name":  curve("ecdsa-sha2-nistp521", "other"),
			"sk-ecdsa with a wrong curve":  "sk-ecdsa-sha2-nistp256@openssh.com " + base64.StdEncoding.EncodeToString(wire("sk-ecdsa-sha2-nistp256@openssh.com", "nistp384", "p", "app")),
			"sk-ed25519 with a short key":  "sk-ssh-ed25519@openssh.com " + base64.StdEncoding.EncodeToString(wire("sk-ssh-ed25519@openssh.com", "short", "app")),
			"rsa blob with one field":      "ssh-rsa " + base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e")),
			"dss blob with too few fields": "ssh-dss " + base64.StdEncoding.EncodeToString(wire("ssh-dss", "p", "q", "g")),
		} {
			t.Run(name, func(t *testing.T) { wantStatus(t, run(ed.line+"\n"+line+"\n"), result.Warn) })
		}
		// the same shapes, right: ecdsa curves, rsa with e and n, dss with four numbers
		for _, line := range []string{
			curve("ecdsa-sha2-nistp384", "nistp384"),
			curve("ecdsa-sha2-nistp521", "nistp521"),
			"ssh-rsa " + base64.StdEncoding.EncodeToString(wire("ssh-rsa", "e", "n")),
			"ssh-dss " + base64.StdEncoding.EncodeToString(wire("ssh-dss", "p", "q", "g", "y")),
		} {
			wantStatus(t, run(ed.line+"\n"+line+"\n"), result.Fail)
		}
	})
	t.Run("the sk key types", func(t *testing.T) {
		for _, typ := range []string{"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"} {
			b := wire(typ, pk32("x"), "application")
			if typ == "sk-ecdsa-sha2-nistp256@openssh.com" {
				b = wire(typ, "nistp256", "point", "application")
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
		wantStatus(t, run(line+"\n"), result.Warn)
		wantStatus(t, run("ssh-ed25519 "+base64.StdEncoding.EncodeToString([]byte{0, 1})+"\n"), result.Warn)
	})
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

// TestAuthorizedKeysLinesMatchSSHKeygen is the differential test of the line
// parser. Every case under testdata/<release>/keycases is one authorized_keys
// line (see keycases.sh) together with what "ssh-keygen -lf" printed for it on
// that release. ssh-keygen reads the line the way sshd does, so the contract
// is: keepwatch finds the very key ssh-keygen finds, or, where ssh-keygen finds
// none, none. The only line keepwatch deliberately does not list although
// ssh-keygen does is a certificate, which it reports as a line that is not a
// key.
func TestAuthorizedKeysLinesMatchSSHKeygen(t *testing.T) {
	const dummy = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, v := range versions {
		dir := "testdata/" + v + "/keycases"
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		cases := 0
		for _, e := range entries {
			id, ok := strings.CutSuffix(e.Name(), ".keys")
			if !ok {
				continue
			}
			cases++
			t.Run(v+"/"+id, func(t *testing.T) {
				content := fixtureFile(t, v+"/keycases/"+id+".keys")
				about := strings.TrimSpace(fixtureFile(t, v+"/keycases/"+id+".about"))
				exit := strings.TrimSpace(fixtureFile(t, v+"/keycases/"+id+".exit"))
				fsys := keyHost(t, v, map[string]string{aliceAK: content})
				run := func(fp string) probes.Outcome {
					return execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {fp}})
				}
				if exit != "0" {
					o := run(dummy)
					wantStatus(t, o, result.Warn)
					for _, ev := range o.Evidence {
						if ev.Subject != "alice:"+dummy && !strings.Contains(ev.Detail, "line is not a public key") {
							t.Fatalf("%s: ssh-keygen finds no key, keepwatch says %+v", about, ev)
						}
					}
					if len(o.Evidence) < 2 {
						t.Fatalf("%s: the line is not reported as unparseable: %+v", about, o.Evidence)
					}
					return
				}
				out := strings.TrimSpace(fixtureFile(t, v+"/keycases/"+id+".fp"))
				fields := strings.Fields(out)
				fp := fields[1]
				if strings.HasSuffix(out, "-CERT)") {
					o := run(fp)
					wantStatus(t, o, result.Warn)
					if strings.Contains(allText(o), "ssh-keygen") || len(o.Evidence) < 2 {
						t.Fatalf("%s: %+v", about, o.Evidence)
					}
					return
				}
				// the line holds exactly the key ssh-keygen found: expecting it passes,
				// expecting something else fails with that key as the subject
				wantStatus(t, run(fp), result.Pass)
				o := run(dummy)
				wantStatus(t, o, result.Fail)
				if !eq(subjects(o), []string{"alice:" + fp}) {
					t.Fatalf("%s: ssh-keygen lists %s, keepwatch lists %v", about, fp, subjects(o))
				}
			})
		}
		if cases < 40 {
			t.Fatalf("%s: only %d key line cases found", v, cases)
		}
	}
}
