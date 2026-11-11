package probes_test

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// A corpusRole is one place in the four probes where text taken from the host
// reaches a subject, a summary, a cause or a detail. run builds a host in
// which frag stands at that place and returns what the probe made of it.
type corpusRole struct {
	name   string
	kind   string
	status result.Status
	// noCtl: the host cannot give this place a control character (the
	// configuration rejects a path or pattern that has one).
	noCtl bool
	// noWS: the host cannot give this place white space (sshd -T prints the
	// value as one word).
	noWS bool
	// url: where a URL with user info can stand: "" nowhere, "full" as a
	// text of its own (it holds the "//"), "host" after a scheme the place
	// supplies itself.
	url string
	// maxPad: the probe reads this place with a small limit (the name of a
	// process), so the padding is cut to this many characters
	maxPad int
	run    func(t *testing.T, frag string) probes.Outcome
}

var (
	pemOnce           sync.Once
	pemExpired, pemOK string
)

// certPEMs returns a certificate that expires in a few days and one that is
// valid for a long time. Making a key costs more than the probes do.
func certPEMs(t *testing.T) (expired, valid string) {
	t.Helper()
	pemOnce.Do(func() {
		pemExpired = pemCert(t, "site.example.test", time.Now().Add(-days(3)))
		pemOK = pemCert(t, "site.example.test", time.Now().Add(days(200)))
	})
	return pemExpired, pemOK
}

// mountLine is a mountinfo line for a mount point as the kernel writes it:
// the white space and the backslash of the path are octal escapes.
func mountLine(id int, point, fstype string) string {
	esc := strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`, "\n", `\012`).Replace(point)
	return mi(id, esc, fstype)
}

func corpusRoles() []corpusRole {
	none := func() *fake.FakeRunner { return newRunner().AddResult(dockerPs, inline("", 0)) }
	cmd := func(args ...string) string { return "/usr/bin/dockerd\x00" + strings.Join(args, "\x00") + "\x00" }
	dockerFS := func(t *testing.T, fsys probestest.FakeFS) probes.Outcome { return exec(dockerProbe(t), none(), fsys) }
	dockerHosts := func(t *testing.T, hosts ...string) string {
		b, err := json.Marshal(map[string]any{"hosts": hosts})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	certPath := func(f string) string { return "/opt/certs/" + f + ".pem" }
	certGlob := func(t *testing.T, files map[string]string, paths ...string) probes.Outcome {
		pl := make([]any, len(paths))
		for i, p := range paths {
			pl[i] = p
		}
		return execCert(certProbe(t, map[string]any{"paths": pl, "globs": []any{"/opt/certs/*.pem"}}), certFS(files))
	}
	certList := func(t *testing.T, f string, fsys probes.FS) probes.Outcome {
		return execCert(certProbe(t, map[string]any{"paths": []any{certPath(f)}, "globs": []any{}}), fsys)
	}
	diskOn := func(t *testing.T, f string, st func(point string) *statfsMap) probes.Outcome {
		point := "/mnt/" + f
		return execDisk(diskProbe(t, map[string]any{"fstypes": []any{"ext4"}}), mountFS(mountLine(7, point, "ext4")), st(point))
	}
	aliceFS := func() probestest.FakeFS {
		return probestest.FakeFS{Files: map[string]string{"/etc/passwd": "alice:x:1001:1001::/home/alice:/bin/bash\n"}}
	}
	keys := func(t *testing.T, fsys probestest.FakeFS, lines ...string) probes.Outcome {
		return execKeys(keysProbe(t), sshdWith(lines...), fsys, map[string][]string{"alice": {}})
	}
	inspected := func(t *testing.T, mut func(c map[string]any)) probes.Outcome {
		ids := idsN(1)
		r := newRunner().AddResult(dockerPs, psOut(ids)).AddResult(inspectArgv(ids...), inline(inspectDoc(ids, func(_ int, c map[string]any) { mut(c) }), 0))
		return exec(dockerProbe(t), r, probestest.FakeFS{})
	}

	return []corpusRole{
		// cert_expiry
		{name: "cert failing item", kind: "cert_expiry", status: result.Fail, run: func(t *testing.T, f string) probes.Outcome {
			ex, _ := certPEMs(t)
			return certGlob(t, map[string]string{certPath(f): ex})
		}},
		{name: "cert partial result", kind: "cert_expiry", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			ex, _ := certPEMs(t)
			return certGlob(t, map[string]string{certPath(f): ex}, "/opt/certs/missing.pem")
		}},
		{name: "cert soonest path of a passing check", kind: "cert_expiry", status: result.Pass, run: func(t *testing.T, f string) probes.Outcome {
			_, ok := certPEMs(t)
			return certGlob(t, map[string]string{certPath(f): ok})
		}},
		{name: "cert file behind a link", kind: "cert_expiry", status: result.Fail, noCtl: true, run: func(t *testing.T, f string) probes.Outcome {
			ex, _ := certPEMs(t)
			fsys := resolvingFS{FakeFS: certFS(map[string]string{certPath("link"): ex}), to: "/opt/archive/" + f + ".pem"}
			return certList(t, "link", fsys)
		}},
		{name: "cert listed path that does not exist", kind: "cert_expiry", status: result.Error, noCtl: true, run: func(t *testing.T, f string) probes.Outcome {
			return certList(t, f, certFS(map[string]string{}))
		}},
		{name: "cert file that is too large", kind: "cert_expiry", status: result.Error, noCtl: true, run: func(t *testing.T, f string) probes.Outcome {
			return certList(t, f, certFS(map[string]string{certPath(f): strings.Repeat("x", 2<<20)}))
		}},
		{name: "cert file that cannot be read", kind: "cert_expiry", status: result.Error, noCtl: true, run: func(t *testing.T, f string) probes.Outcome {
			fsys := certFS(map[string]string{})
			fsys.Errs = map[string]error{certPath(f): errors.New("denied")}
			return certList(t, f, fsys)
		}},
		{name: "cert read error text", kind: "cert_expiry", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			fsys := certFS(map[string]string{})
			fsys.Errs = map[string]error{certPath("fixed"): errors.New("denied " + f)}
			return certList(t, "fixed", fsys)
		}},
		{name: "cert file that is no certificate", kind: "cert_expiry", status: result.Error, noCtl: true, run: func(t *testing.T, f string) probes.Outcome {
			return certList(t, f, certFS(map[string]string{certPath(f): "not a certificate"}))
		}},
		{name: "cert glob that fails", kind: "cert_expiry", status: result.Error, noCtl: true, run: func(t *testing.T, f string) probes.Outcome {
			fsys := certFS(map[string]string{})
			fsys.GlobErr = errors.New("boom")
			return execCert(certProbe(t, map[string]any{"paths": []any{}, "globs": []any{"/opt/certs/" + f + "/*.pem"}}), fsys)
		}},
		{name: "cert glob error text", kind: "cert_expiry", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			fsys := certFS(map[string]string{})
			fsys.GlobErr = errors.New("boom " + f)
			return execCert(certProbe(t, map[string]any{"paths": []any{}, "globs": []any{"/opt/certs/*.pem"}}), fsys)
		}},
		{name: "cert common name", kind: "cert_expiry", status: result.Fail, run: func(t *testing.T, f string) probes.Outcome {
			cn := pemCert(t, f, time.Now().Add(-days(3)))
			return execCert(certProbe(t, map[string]any{"paths": []any{"/opt/cn.pem"}, "globs": []any{}}), certFS(map[string]string{"/opt/cn.pem": cn}))
		}},

		// disk_usage
		{name: "disk failing item", kind: "disk_usage", status: result.Fail, url: "full", run: func(t *testing.T, f string) probes.Outcome {
			return diskOn(t, f, func(p string) *statfsMap { return &statfsMap{by: map[string]probes.Statfs{p: usage(95, 1)}} })
		}},
		{name: "disk statfs error", kind: "disk_usage", status: result.Error, url: "full", run: func(t *testing.T, f string) probes.Outcome {
			return diskOn(t, f, func(p string) *statfsMap { return &statfsMap{errs: map[string]error{p: errors.New("boom")}} })
		}},
		{name: "disk statfs error text", kind: "disk_usage", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return execDisk(diskProbe(t, map[string]any{"fstypes": []any{"ext4"}}), mountFS(mi(7, "/mnt/data", "ext4")), &statfsMap{errs: map[string]error{"/mnt/data": errors.New("boom " + f)}})
		}},
		{name: "disk inconsistent numbers", kind: "disk_usage", status: result.Error, url: "full", run: func(t *testing.T, f string) probes.Outcome {
			return diskOn(t, f, func(p string) *statfsMap {
				return &statfsMap{by: map[string]probes.Statfs{p: {BlockSize: 4096, Blocks: 1, Bfree: 2, Bavail: 2}}}
			})
		}},

		// docker_exposure
		{name: "docker TCP finding", kind: "docker_exposure", status: result.Fail, url: "host", run: func(t *testing.T, f string) probes.Outcome {
			return dockerFS(t, dockerHost(dockerHosts(t, "tcp://"+f), ""))
		}},
		{name: "docker host in daemon.json that is not understood", kind: "docker_exposure", status: result.Error, url: "host", run: func(t *testing.T, f string) probes.Outcome {
			return dockerFS(t, dockerHost(dockerHosts(t, "ftp://"+f), ""))
		}},
		{name: "docker host on the command line that is not understood", kind: "docker_exposure", status: result.Error, url: "host", run: func(t *testing.T, f string) probes.Outcome {
			return dockerFS(t, dockerHost("", cmd("-H", "ftp://"+f)))
		}},
		{name: "docker tls flag with a bad value", kind: "docker_exposure", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return dockerFS(t, dockerHost("", cmd("--tls="+f)))
		}},
		{name: "docker group of flags that cannot be read", kind: "docker_exposure", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return dockerFS(t, dockerHost("", cmd("-zH"+f)))
		}},
		{name: "docker config file that is not absolute", kind: "docker_exposure", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return dockerFS(t, dockerHost("", cmd("--config-file", "rel/"+f)))
		}},
		{name: "docker config file that cannot be read", kind: "docker_exposure", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			fsys := dockerHost("", cmd("--config-file", "/etc/"+f+".json"))
			fsys.Errs = map[string]error{"/etc/" + f + ".json": errors.New("denied")}
			return dockerFS(t, fsys)
		}},
		{name: "docker config file read error text", kind: "docker_exposure", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			fsys := dockerHost("", cmd("--config-file", "/etc/fixed.json"))
			fsys.Errs = map[string]error{"/etc/fixed.json": errors.New("denied " + f)}
			return dockerFS(t, fsys)
		}},
		{name: "docker config file that does not parse", kind: "docker_exposure", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			fsys := dockerHost("", cmd("--config-file", "/etc/"+f+".json"))
			fsys.Files["/etc/"+f+".json"] = "{"
			return dockerFS(t, fsys)
		}},
		{name: "docker pid file that cannot be read", kind: "docker_exposure", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			fsys := dockerHost("", "")
			fsys.Errs = map[string]error{"/run/docker.pid": errors.New("denied " + f)}
			return dockerFS(t, fsys)
		}},
		{name: "docker process that is not dockerd", kind: "docker_exposure", status: result.Error, maxPad: 5, run: func(t *testing.T, f string) probes.Outcome {
			fsys := dockerHost("", cmd("-H", "tcp://127.0.0.1:2375"))
			fsys.Files["/proc/4242/comm"] = f + "\n"
			return dockerFS(t, fsys)
		}},
		{name: "docker ps output that is no container id", kind: "docker_exposure", status: result.Error, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			r := newRunner().AddResult(dockerPs, inline(f+"\n", 0))
			return exec(dockerProbe(t), r, probestest.FakeFS{})
		}},
		{name: "docker container that mounts a socket", kind: "docker_exposure", status: result.Fail, run: func(t *testing.T, f string) probes.Outcome {
			return inspected(t, func(c map[string]any) {
				c["Mounts"] = []any{map[string]any{"Type": "bind", "Source": "/run/" + f + "/docker.sock"}}
			})
		}},
		{name: "docker container with a name of its own", kind: "docker_exposure", status: result.Fail, run: func(t *testing.T, f string) probes.Outcome {
			return inspected(t, func(c map[string]any) {
				c["Name"] = "/" + f + " name"
				hostConfig(c)["Privileged"] = true
			})
		}},

		// authorized_keys
		{name: "authorized_keys pattern warning", kind: "authorized_keys", status: result.Warn, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return keys(t, aliceFS(), "authorizedkeysfile .ssh/"+f+"/%x", "authorizedkeyscommand none")
		}},
		{name: "authorized_keys file that cannot be read", kind: "authorized_keys", status: result.Warn, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			fsys := aliceFS()
			fsys.Errs = map[string]error{"/home/alice\x00.ssh/" + f: errors.New("io " + f)}
			return keys(t, fsys, "authorizedkeysfile .ssh/"+f, "authorizedkeyscommand none")
		}},
		{name: "authorized_keys line that is no key", kind: "authorized_keys", status: result.Warn, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			fsys := aliceFS()
			fsys.Homes = map[string]string{"/home/alice\x00.ssh/" + f: "AAAA\n"}
			return keys(t, fsys, "authorizedkeysfile .ssh/"+f, "authorizedkeyscommand none")
		}},
		{name: "authorized_keys key in a file", kind: "authorized_keys", status: result.Fail, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			ed := loadKey(t, "ubuntu2404", "ed25519")
			fsys := aliceFS()
			fsys.Homes = map[string]string{"/home/alice\x00.ssh/" + f: ed.line + "\n"}
			return keys(t, fsys, "authorizedkeysfile .ssh/"+f, "authorizedkeyscommand none")
		}},
		{name: "authorized_keys command", kind: "authorized_keys", status: result.Warn, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return keys(t, aliceFS(), "authorizedkeysfile .ssh/authorized_keys", "authorizedkeyscommand "+f)
		}},
		{name: "authorized_keys sshd line that is no keyword line", kind: "authorized_keys", status: result.Error, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			r := newRunner().AddResult(sshdArgv, inline(f+"\n", 0))
			return execKeys(keysProbe(t), r, aliceFS(), map[string][]string{"alice": {}})
		}},
		{name: "authorized_keys passwd that cannot be read", kind: "authorized_keys", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			fsys := aliceFS()
			fsys.Errs = map[string]error{"/etc/passwd": errors.New("denied " + f)}
			return keys(t, fsys, "authorizedkeysfile .ssh/authorized_keys", "authorizedkeyscommand none")
		}},
	}
}
