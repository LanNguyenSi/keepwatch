package probes_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// keyCase is one authorized_keys line of testdata/<release>/keycases with what
// ssh-keygen and a real sshd made of it on that release (see keycases.sh).
type keyCase struct {
	id, about, line string
	keygenExit      string
	keygenFP        string   // the fingerprint "ssh-keygen -lf" printed, "" when it printed none
	keygenCert      bool     // ... and it is a certificate
	accepted        []string // the keys sshd accepted for a login: good, evil, rsa, ecdsa, goodcert
}

func loadKeyCases(t *testing.T, v string) (cases []keyCase, fps map[string]string) {
	t.Helper()
	fps = map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(fixtureFile(t, v+"/keycases/KEYS")), "\n") {
		f := strings.Fields(l)
		fps[f[0]] = f[1]
	}
	entries, err := os.ReadDir("testdata/" + v + "/keycases")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".keys")
		if !ok {
			continue
		}
		c := keyCase{
			id:         id,
			about:      strings.TrimSpace(fixtureFile(t, v+"/keycases/"+id+".about")),
			line:       fixtureFile(t, v+"/keycases/"+id+".keys"),
			keygenExit: strings.TrimSpace(fixtureFile(t, v+"/keycases/"+id+".exit")),
		}
		if c.keygenExit == "0" {
			out := strings.TrimSpace(fixtureFile(t, v+"/keycases/"+id+".fp"))
			c.keygenFP = strings.Fields(out)[1]
			c.keygenCert = strings.HasSuffix(out, "-CERT)")
		}
		if login := strings.TrimSpace(fixtureFile(t, v+"/keycases/"+id+".login")); login != "none" {
			c.accepted = strings.Fields(login)
		}
		cases = append(cases, c)
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].id < cases[j].id })
	return cases, fps
}

// TestAuthorizedKeysMatchWhatSSHDAccepts is the differential test of the line
// parser against the real programs. Every case is one authorized_keys line,
// the output of "ssh-keygen -lf" for it, and which of the keys good, evil, rsa,
// ecdsa and a certificate a real sshd (OpenSSH 8.9p1 on Ubuntu 22.04, 9.6p1 on
// 24.04) accepted for a login with the line as the user's only authorized key.
// The contract, with the expected key list holding only a placeholder so that
// every key keepwatch finds is reported:
//
//   - a key that sshd accepts is listed, by exactly its fingerprint;
//   - keepwatch lists no key that neither sshd accepts nor ssh-keygen lists
//     (a key that ssh-keygen lists and sshd refuses may be listed: a false
//     alarm is the safe direction);
//   - a line that sshd accepts a key from is never silent: the run fails.
func TestAuthorizedKeysMatchWhatSSHDAccepts(t *testing.T) {
	const dummy = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, v := range versions {
		cases, fps := loadKeyCases(t, v)
		if len(cases) < 80 {
			t.Fatalf("%s: only %d key line cases found", v, len(cases))
		}
		accepting := 0
		for _, c := range cases {
			t.Run(v+"/"+c.id, func(t *testing.T) {
				fsys := keyHost(t, v, map[string]string{aliceAK: c.line})
				o := execKeys(keysProbe(t), sshdFixture(v, "sshd_T_default"), fsys, map[string][]string{"alice": {dummy}})
				listed := map[string]bool{}
				unreadable := 0
				for _, e := range o.Evidence {
					if fp, ok := strings.CutPrefix(e.Subject, "alice:SHA256:"); ok && o.Status == result.Fail {
						listed["SHA256:"+fp] = true
					}
					if strings.Contains(e.Detail, "may hold an unchecked key") {
						unreadable++
					}
				}
				allowed := map[string]bool{c.keygenFP: c.keygenFP != "" && !c.keygenCert}
				for _, k := range c.accepted {
					if k != "goodcert" {
						allowed[fps[k]] = true
						if !listed[fps[k]] {
							t.Errorf("%s: sshd accepts the key %q, keepwatch lists %v (status %s)", c.about, k, listed, o.Status)
						}
					}
				}
				for fp := range listed {
					if !allowed[fp] {
						t.Errorf("%s: keepwatch lists %s, which neither sshd accepts nor ssh-keygen lists (ssh-keygen: %q, sshd: %v)", c.about, fp, c.keygenFP, c.accepted)
					}
				}
				if len(c.accepted) > 0 {
					accepting++
					if o.Status == result.Pass || o.Status == result.Warn {
						t.Errorf("%s: sshd accepts %v and the run is %s", c.about, c.accepted, o.Status)
					}
				}
				if len(c.accepted) == 0 && c.keygenFP == "" && len(listed) > 0 {
					t.Errorf("%s: neither sshd nor ssh-keygen accepts a key and keepwatch lists %v", c.about, listed)
				}
				if c.keygenCert && len(listed) > 0 {
					t.Errorf("%s: a certificate line is listed as a key: %v", c.about, listed)
				}
			})
		}
		if accepting < 25 {
			t.Fatalf("%s: sshd accepted a key in only %d cases", v, accepting)
		}
	}
}

// The lines that an earlier reader of the file got wrong: sshd accepts a key
// from every one of them, so each is a case with a successful login.
func TestAuthorizedKeysFormsThatSSHDAcceptsAreInTheCorpus(t *testing.T) {
	want := []string{
		"rsa-sha2-256 as the key type",
		"rsa-sha2-512 as the key type",
		"vertical tab inside the base64",
		"form feed inside the base64",
		"carriage return inside the base64",
		"rsa key with a zero byte in front",
		"rsa key with three zero bytes",
	}
	for _, v := range versions {
		cases, _ := loadKeyCases(t, v)
		for _, w := range want {
			found := false
			for _, c := range cases {
				if strings.HasPrefix(c.about, w) {
					found = true
					if len(c.accepted) == 0 {
						t.Errorf("%s: sshd did not accept %q", v, c.about)
					}
				}
			}
			if !found {
				t.Errorf("%s: no case %q", v, w)
			}
		}
		// and the ones sshd refuses although they look like keys
		for _, w := range []string{"RSA, the short name", "ED25519, the short name", "ECDSA, the short name", "ed25519 in lower case", "rsa key with a negative modulus", "ecdsa key with a compressed point"} {
			for _, c := range cases {
				if strings.HasPrefix(c.about, w) && len(c.accepted) != 0 {
					t.Errorf("%s: sshd accepted %q", v, c.about)
				}
			}
		}
	}
}
