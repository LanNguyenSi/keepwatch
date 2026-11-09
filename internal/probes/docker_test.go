package probes_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var dockerPs = []string{"docker", "ps", "-q", "--no-trunc"}

func inspectArgv(ids ...string) []string {
	return append([]string{"docker", "inspect", "--type", "container", "--"}, ids...)
}

func dockerProbe(t *testing.T) probes.Probe { return prepare(t, "docker_exposure", nil) }

// fixtureIDs reads the ids a captured "docker ps" printed.
func fixtureIDs(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".stdout")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

func fixtureFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// dockerHost builds the file system of a docker host: a daemon.json, a pid
// file and the command line of the process it names.
func dockerHost(daemonJSON, cmdline string) probestest.FakeFS {
	files := map[string]string{}
	if daemonJSON != "" {
		files["/etc/docker/daemon.json"] = daemonJSON
	}
	if cmdline != "" {
		files["/run/docker.pid"] = "4242"
		files["/proc/4242/cmdline"] = cmdline
		files["/proc/4242/comm"] = "dockerd\n"
	}
	return probestest.FakeFS{Files: files}
}

func TestDockerCapturedContainers(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			ids := fixtureIDs(t, v+"/docker_ps_mixed")
			r := newRunner().Add(dockerPs, v+"/docker_ps_mixed").Add(inspectArgv(ids...), v+"/docker_inspect_mixed")
			o := exec(dockerProbe(t), r, dockerHost(fixtureFile(t, v+"/daemon_json_plain.stdout"), fixtureFile(t, v+"/dockerd_cmdline_plain.stdout")))
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"kwall", "kwhostnet", "kwhostpid", "kwpriv", "kwsock"}) {
				t.Fatalf("subjects = %v", subjects(o))
			}
			want := map[string]string{
				"kwall":     "privileged; host PID namespace; host network namespace; docker socket mounted (/run/docker.sock)",
				"kwhostnet": "host network namespace",
				"kwhostpid": "host PID namespace",
				"kwpriv":    "privileged",
				"kwsock":    "docker socket mounted (/var/run/docker.sock)",
			}
			for _, e := range o.Evidence {
				if e.Detail != want[e.Subject] {
					t.Errorf("%s: detail %q, want %q", e.Subject, e.Detail, want[e.Subject])
				}
			}
		})
	}
}

func TestDockerCapturedDaemon(t *testing.T) {
	for _, v := range versions {
		none := newRunner().Add(dockerPs, v+"/docker_ps_none")
		plain := fixtureFile(t, v+"/dockerd_cmdline_plain.stdout")
		t.Run(v+"/plain daemon, no containers", func(t *testing.T) {
			o := exec(dockerProbe(t), none, dockerHost(fixtureFile(t, v+"/daemon_json_plain.stdout"), plain))
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "0 running container(s)")
		})
		t.Run(v+"/tcp host in daemon.json", func(t *testing.T) {
			o := exec(dockerProbe(t), none, dockerHost(fixtureFile(t, v+"/daemon_json_tcp.stdout"), fixtureFile(t, v+"/dockerd_cmdline_hostsfile.stdout")))
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"daemon.json tcp://127.0.0.1:2375"}) || !strings.Contains(o.Evidence[0].Detail, "no TLS") {
				t.Fatalf("evidence %+v", o.Evidence)
			}
		})
		t.Run(v+"/tcp host on the command line", func(t *testing.T) {
			o := exec(dockerProbe(t), none, dockerHost(fixtureFile(t, v+"/daemon_json_plain.stdout"), fixtureFile(t, v+"/dockerd_cmdline_tcp.stdout")))
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"dockerd tcp://127.0.0.1:2375"}) {
				t.Fatalf("evidence %+v", o.Evidence)
			}
		})
		t.Run(v+"/tcp host in a group of combined flags (dockerd -DH tcp://...)", func(t *testing.T) {
			o := exec(dockerProbe(t), none, dockerHost(fixtureFile(t, v+"/daemon_json_plain.stdout"), fixtureFile(t, v+"/dockerd_cmdline_group.stdout")))
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"dockerd tcp://127.0.0.1:2375"}) {
				t.Fatalf("evidence %+v", o.Evidence)
			}
		})
		t.Run(v+"/the captured process name is what the probe expects", func(t *testing.T) {
			if got := strings.TrimSpace(fixtureFile(t, v+"/dockerd_comm.stdout")); got != "dockerd" {
				t.Fatalf("comm %q", got)
			}
			if got := strings.TrimSpace(fixtureFile(t, v+"/dockerd_proc_owner.stdout")); got != "0" {
				t.Fatalf("owner %q", got)
			}
		})
		t.Run(v+"/daemon not reachable", func(t *testing.T) {
			r := newRunner().Add(dockerPs, v+"/docker_ps_nodaemon")
			o := exec(dockerProbe(t), r, dockerHost(fixtureFile(t, v+"/daemon_json_plain.stdout"), ""))
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "docker daemon not reachable")
		})
		t.Run(v+"/daemon not reachable keeps the tcp finding", func(t *testing.T) {
			r := newRunner().Add(dockerPs, v+"/docker_ps_nodaemon")
			o := exec(dockerProbe(t), r, dockerHost(fixtureFile(t, v+"/daemon_json_tcp.stdout"), ""))
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "partial")
			if !eq(subjects(o), []string{"daemon.json tcp://127.0.0.1:2375"}) {
				t.Fatalf("evidence %+v", o.Evidence)
			}
		})
		t.Run(v+"/a container stopped between the two commands", func(t *testing.T) {
			ids := fixtureIDs(t, v+"/docker_ps_mixed")
			zero := strings.Repeat("0", 64)
			r := newRunner().
				AddResult(dockerPs, inline(ids[0]+"\n"+zero+"\n", 0)).
				Add(inspectArgv(ids[0], zero), v+"/docker_inspect_gone")
			o := exec(dockerProbe(t), r, dockerHost(fixtureFile(t, v+"/daemon_json_plain.stdout"), ""))
			if o.Status != result.Pass && o.Status != result.Fail {
				t.Fatalf("status %s (%s)", o.Status, o.Summary)
			}
			wantSummary(t, o, "1 container(s) stopped while they were examined")
		})
	}
}

func TestDockerNotInstalled(t *testing.T) {
	missing := newRunner().AddError(dockerPs, execx.ErrNotFound)
	t.Run("nothing at all", func(t *testing.T) {
		wantStatus(t, exec(dockerProbe(t), missing, probestest.FakeFS{}), result.Skipped)
	})
	t.Run("a leftover daemon.json", func(t *testing.T) {
		o := exec(dockerProbe(t), missing, dockerHost(`{"hosts": ["unix:///var/run/docker.sock"]}`, ""))
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "docker is not installed, containers not examined")
	})
	t.Run("a daemon.json with a tcp host and no docker cli", func(t *testing.T) {
		o := exec(dockerProbe(t), missing, dockerHost(`{"hosts": ["tcp://0.0.0.0:2375"]}`, ""))
		wantStatus(t, o, result.Fail)
	})
	t.Run("only a pid file: a running dockerd and no docker command is an error", func(t *testing.T) {
		o := exec(dockerProbe(t), missing, dockerHost("", "dockerd\x00-H\x00tcp://0.0.0.0:2375\x00"))
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "dockerd is running but the docker command is not installed")
		if !eq(subjects(o), []string{"dockerd tcp://0.0.0.0:2375"}) {
			t.Fatalf("the confirmed finding is lost: %+v", o.Evidence)
		}
	})
	t.Run("a stale pid file and no docker command is not an error", func(t *testing.T) {
		fsys := probestest.FakeFS{Files: map[string]string{"/run/docker.pid": "4242"}}
		wantStatus(t, exec(dockerProbe(t), missing, fsys), result.Pass)
	})
}

func TestDockerHostEntries(t *testing.T) {
	cases := []struct {
		host string
		want result.Status
	}{
		{"tcp://0.0.0.0:2375", result.Fail},
		{"TCP://0.0.0.0:2375", result.Fail},
		{"tcp://", result.Fail},
		{"0.0.0.0:2375", result.Fail}, // no scheme: dockerd treats it as TCP
		{"localhost:2375", result.Fail},
		{"unix:///var/run/docker.sock", result.Pass},
		{"UNIX:///run/docker.sock", result.Pass},
		{"fd://", result.Pass},
		{"npipe:////./pipe/docker_engine", result.Pass},
		{"ftp://example.test", result.Error},
		{"", result.Error},
		{"  ", result.Error},
	}
	none := newRunner().AddResult(dockerPs, inline("", 0))
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"hosts": []string{c.host}})
			wantStatus(t, exec(dockerProbe(t), none, dockerHost(string(b), "")), c.want)
		})
	}
	t.Run("both a safe and an unsafe host", func(t *testing.T) {
		o := exec(dockerProbe(t), none, dockerHost(`{"hosts": ["fd://", "tcp://192.0.2.1:2376"]}`, ""))
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"daemon.json tcp://192.0.2.1:2376"}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("tls settings are named", func(t *testing.T) {
		for cfg, want := range map[string]string{
			`{"hosts": ["tcp://0.0.0.0:2376"]}`:                       "no TLS",
			`{"hosts": ["tcp://0.0.0.0:2376"], "tls": true}`:          "tls on, clients not verified",
			`{"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": true}`:    "tlsverify on",
			`{"hosts": ["tcp://0.0.0.0:2376"], "tls": "yes"}`:         "no TLS",
			`{"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": false}`:   "no TLS",
			`{"tlsverify": true, "hosts": ["tcp://0.0.0.0:2376"]}`:    "tlsverify on",
			`{"hosts": ["tcp://0.0.0.0:2376"], "tls": true, "x": []}`: "tls on",
		} {
			o := exec(dockerProbe(t), none, dockerHost(cfg, ""))
			wantStatus(t, o, result.Fail)
			if !strings.Contains(o.Evidence[0].Detail, want) {
				t.Errorf("%s: detail %q lacks %q", cfg, o.Evidence[0].Detail, want)
			}
		}
	})
	t.Run("daemon.json that is not understood is an error", func(t *testing.T) {
		for _, cfg := range []string{"null", "[]", `"x"`, "{", `{"hosts": "tcp://x"}`, `{"hosts": [1]}`, `{"hosts": {"a": 1}}`} {
			o := exec(dockerProbe(t), none, dockerHost(cfg, ""))
			if o.Status != result.Error {
				t.Errorf("%s: status %s (%s)", cfg, o.Status, o.Summary)
			}
		}
		wantStatus(t, exec(dockerProbe(t), none, dockerHost(`{}`, "")), result.Pass)
		wantStatus(t, exec(dockerProbe(t), none, dockerHost(`{"hosts": null}`, "")), result.Pass)
	})
	t.Run("daemon.json that cannot be read or is too large", func(t *testing.T) {
		fsys := dockerHost("", "")
		fsys.Errs = map[string]error{"/etc/docker/daemon.json": fs.ErrPermission}
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Error)
		fsys = dockerHost(strings.Repeat(" ", 2<<20)+"{}", "")
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Error)
	})
}

func TestDockerCommandLine(t *testing.T) {
	none := newRunner().AddResult(dockerPs, inline("", 0))
	cmd := func(args ...string) string { return "/usr/bin/dockerd\x00" + strings.Join(args, "\x00") + "\x00" }
	cases := []struct {
		name string
		args []string
		want result.Status
		sub  string
	}{
		{"-H separate", []string{"-H", "tcp://0.0.0.0:2375"}, result.Fail, "dockerd tcp://0.0.0.0:2375"},
		{"-H glued", []string{"-Htcp://0.0.0.0:2375"}, result.Fail, "dockerd tcp://0.0.0.0:2375"},
		{"-H=", []string{"-H=tcp://0.0.0.0:2375"}, result.Fail, "dockerd tcp://0.0.0.0:2375"},
		{"--host separate", []string{"--host", "tcp://0.0.0.0:2375"}, result.Fail, "dockerd tcp://0.0.0.0:2375"},
		{"--host=", []string{"--host=tcp://0.0.0.0:2375"}, result.Fail, "dockerd tcp://0.0.0.0:2375"},
		{"bare host:port", []string{"-H", "0.0.0.0:2375"}, result.Fail, "dockerd 0.0.0.0:2375"},
		{"fd only", []string{"-H", "fd://", "--containerd=/run/containerd/containerd.sock"}, result.Pass, ""},
		{"unix and tcp", []string{"-H", "unix:///var/run/docker.sock", "-H", "tcp://127.0.0.1:2375"}, result.Fail, "dockerd tcp://127.0.0.1:2375"},
		{"two tcp hosts", []string{"-H", "tcp://0.0.0.0:2375", "-H", "tcp://0.0.0.0:2376"}, result.Fail, "dockerd tcp://0.0.0.0:2376"},
		{"-H without value", []string{"-H"}, result.Error, "without a value"},
		{"--host without value", []string{"--host"}, result.Error, "without a value"},
		{"unknown scheme", []string{"-H", "gopher://x"}, result.Error, "not understood"},
		{"after --", []string{"--", "-H", "tcp://0.0.0.0:2375"}, result.Pass, ""},
		{"tlsverify", []string{"--tlsverify", "-H", "tcp://0.0.0.0:2376"}, result.Fail, "tlsverify on"},
		{"tls", []string{"--tls=true", "-H", "tcp://0.0.0.0:2376"}, result.Fail, "tls on, clients not verified"},
		{"tls after the host", []string{"-H", "tcp://0.0.0.0:2376", "--tlsverify=true"}, result.Fail, "tlsverify on"},
		{"unrelated flags", []string{"--log-level=debug", "-D", "--data-root", "/srv/docker"}, result.Pass, ""},
		{"a flag value that looks like a host", []string{"--data-root", "-Htcp://x"}, result.Fail, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := exec(dockerProbe(t), none, dockerHost("", cmd(c.args...)))
			wantStatus(t, o, c.want)
			if c.sub != "" && !strings.Contains(allText(o), c.sub) {
				t.Fatalf("%q lacks %q", allText(o), c.sub)
			}
		})
	}
	t.Run("config file named on the command line replaces daemon.json", func(t *testing.T) {
		for _, args := range [][]string{{"--config-file", "/etc/alt.json"}, {"--config-file=/etc/alt.json"}} {
			fsys := dockerHost(`{"hosts": ["tcp://198.51.100.1:1"]}`, cmd(args...))
			fsys.Files["/etc/alt.json"] = `{"hosts": ["tcp://203.0.113.1:2"]}`
			o := exec(dockerProbe(t), none, fsys)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"daemon.json tcp://203.0.113.1:2"}) {
				t.Fatalf("subjects %v", subjects(o))
			}
		}
		fsys := dockerHost(`{"hosts": ["tcp://198.51.100.1:1"]}`, cmd("--config-file", "/etc/none.json"))
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Pass)
		wantStatus(t, exec(dockerProbe(t), none, dockerHost("", cmd("--config-file", "relative.json"))), result.Error)
		wantStatus(t, exec(dockerProbe(t), none, dockerHost("", cmd("--config-file"))), result.Error)
	})
	t.Run("a pid that is not a dockerd", func(t *testing.T) {
		// the command line says sshd
		o := exec(dockerProbe(t), none, dockerHost("", "/usr/sbin/sshd\x00-H\x00tcp://0.0.0.0:2375\x00"))
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "not dockerd")
		// the process name says sshd
		fsys := dockerHost("", cmd("-H", "tcp://0.0.0.0:2375"))
		fsys.Files["/proc/4242/comm"] = "sshd\n"
		o = exec(dockerProbe(t), none, fsys)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "not dockerd")
		if len(o.Evidence) != 0 {
			t.Fatalf("the command line of a process that is not the daemon was read: %+v", o.Evidence)
		}
	})
	t.Run("a pid of a process that root does not own is not trusted", func(t *testing.T) {
		// pid reuse: a process of an unprivileged user, whose --config-file would be read as root
		fsys := dockerHost("", cmd("--config-file", "/etc/alt.json", "-H", "tcp://0.0.0.0:2375"))
		fsys.Files["/etc/alt.json"] = `{"hosts": ["tcp://198.51.100.1:1"]}`
		fsys.Owners = map[string]uint32{"/proc/4242": 1000}
		o := exec(dockerProbe(t), none, fsys)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "owned by uid 1000")
		if len(o.Evidence) != 0 {
			t.Fatalf("that process's arguments were used: %+v", o.Evidence)
		}
		fsys.Owners = map[string]uint32{"/proc/4242": 0}
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Fail)
	})
	t.Run("the owner cannot be told", func(t *testing.T) {
		fsys := dockerHost("", cmd())
		fsys.Errs = map[string]error{"/proc/4242": fs.ErrPermission}
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Error)
		// a file system without the operation
		files := probestest.MemFS{"/run/docker.pid": "4242", "/proc/4242/cmdline": cmd(), "/proc/4242/comm": "dockerd\n"}
		wantStatus(t, exec(dockerProbe(t), none, files), result.Error)
	})
	t.Run("the process vanishes after its owner was read", func(t *testing.T) {
		fsys := dockerHost("", cmd())
		fsys.Errs = map[string]error{"/proc/4242/comm": fs.ErrNotExist}
		o := exec(dockerProbe(t), none, fsys)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "stale")
	})
	t.Run("a dockerd under another path", func(t *testing.T) {
		wantStatus(t, exec(dockerProbe(t), none, dockerHost("", "/opt/x/dockerd\x00-H\x00tcp://0.0.0.0:2375\x00")), result.Fail)
	})
	t.Run("a stale pid file", func(t *testing.T) {
		fsys := probestest.FakeFS{Files: map[string]string{"/run/docker.pid": "4242"}}
		o := exec(dockerProbe(t), none, fsys)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "stale")
	})
	t.Run("the second pid file is used when the first is missing", func(t *testing.T) {
		fsys := probestest.FakeFS{Files: map[string]string{"/var/run/docker.pid": "4242", "/proc/4242/cmdline": cmd("-H", "tcp://0.0.0.0:1"), "/proc/4242/comm": "dockerd\n"}}
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Fail)
	})
	t.Run("pid files that hold no pid", func(t *testing.T) {
		for _, pid := range []string{"", "abc", "12abc", "0", "-5", "042", "1 2", "99999999999999999999"} {
			fsys := probestest.FakeFS{Files: map[string]string{"/run/docker.pid": pid, "/proc/42/cmdline": cmd(), "/proc/42/comm": "dockerd\n"}}
			o := exec(dockerProbe(t), none, fsys)
			if o.Status != result.Error {
				t.Errorf("pid %q: status %s (%s)", pid, o.Status, o.Summary)
			}
		}
		wantStatus(t, exec(dockerProbe(t), none, probestest.FakeFS{Files: map[string]string{"/run/docker.pid": "4242\n", "/proc/4242/cmdline": cmd(), "/proc/4242/comm": "dockerd\n"}}), result.Pass)
	})
	t.Run("unreadable pid file and command line", func(t *testing.T) {
		fsys := probestest.FakeFS{Errs: map[string]error{"/run/docker.pid": fs.ErrPermission}}
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Error)
		fsys = probestest.FakeFS{Files: map[string]string{"/run/docker.pid": "7", "/proc/7/comm": "dockerd\n"}, Errs: map[string]error{"/proc/7/cmdline": fs.ErrPermission}}
		wantStatus(t, exec(dockerProbe(t), none, fsys), result.Error)
	})
}

// inspectDoc builds an inspect document for n containers; mut changes the
// map of container i.
func inspectDoc(ids []string, mut func(i int, c map[string]any)) string {
	var list []map[string]any
	for i, id := range ids {
		c := map[string]any{
			"Id": id, "Name": fmt.Sprintf("/c%03d", i),
			"HostConfig": map[string]any{"Privileged": false, "PidMode": "", "NetworkMode": "bridge", "Binds": nil},
			"Mounts":     []any{},
		}
		if mut != nil {
			mut(i, c)
		}
		list = append(list, c)
	}
	b, _ := json.Marshal(list)
	return string(b)
}

func hostConfig(c map[string]any) map[string]any { return c["HostConfig"].(map[string]any) }

func idsN(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1)
	}
	return ids
}

func psOut(ids []string) execx.Result { return inline(strings.Join(ids, "\n")+"\n", 0) }

func TestDockerInspectOutput(t *testing.T) {
	ids := idsN(1)
	run1 := func(doc string, exit int, stderr string) probes.Outcome {
		r := newRunner().AddResult(dockerPs, psOut(ids)).
			AddResult(inspectArgv(ids...), execx.Result{Stdout: []byte(doc), Stderr: []byte(stderr), ExitCode: exit})
		return exec(dockerProbe(t), r, probestest.FakeFS{})
	}
	t.Run("clean container", func(t *testing.T) {
		o := run1(inspectDoc(ids, nil), 0, "")
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "1 running container(s)")
	})
	t.Run("each reason alone", func(t *testing.T) {
		for want, mut := range map[string]func(int, map[string]any){
			"privileged":             func(_ int, c map[string]any) { hostConfig(c)["Privileged"] = true },
			"host PID namespace":     func(_ int, c map[string]any) { hostConfig(c)["PidMode"] = "host" },
			"host network namespace": func(_ int, c map[string]any) { hostConfig(c)["NetworkMode"] = "host" },
			"docker socket mounted (/run/docker.sock)": func(_ int, c map[string]any) {
				c["Mounts"] = []any{map[string]any{"Type": "bind", "Source": "/run/docker.sock"}}
			},
			"docker socket mounted (/var/run/docker.sock)": func(_ int, c map[string]any) {
				hostConfig(c)["Binds"] = []any{"/var/run/docker.sock:/var/run/docker.sock:ro"}
			},
			"docker socket mounted (/opt/x/docker.sock)": func(_ int, c map[string]any) {
				c["Mounts"] = []any{map[string]any{"Type": "bind", "Source": "/opt/x/docker.sock"}}
			},
		} {
			o := run1(inspectDoc(ids, mut), 0, "")
			wantStatus(t, o, result.Fail)
			if o.Evidence[0].Detail != want {
				t.Errorf("detail %q, want %q", o.Evidence[0].Detail, want)
			}
		}
	})
	t.Run("other namespace modes are not the host's", func(t *testing.T) {
		for _, mode := range []string{"container:abc", "private", "none", "bridge", "default", "myproject_default"} {
			o := run1(inspectDoc(ids, func(_ int, c map[string]any) {
				hostConfig(c)["PidMode"] = mode
				hostConfig(c)["NetworkMode"] = mode
			}), 0, "")
			if o.Status != result.Pass {
				t.Errorf("mode %q: %s %+v", mode, o.Status, o.Evidence)
			}
		}
	})
	t.Run("not a docker socket", func(t *testing.T) {
		for _, src := range []string{"/var/run", "/run", "/", "/var/run/docker.sock.bak", "/var/run/docker.sock/../x", "docker.sock", "/data/docker.socket"} {
			o := run1(inspectDoc(ids, func(_ int, c map[string]any) {
				c["Mounts"] = []any{map[string]any{"Type": "bind", "Source": src}}
				hostConfig(c)["Binds"] = []any{"named-volume:/x", src + ":/y"}
			}), 0, "")
			if o.Status != result.Pass {
				t.Errorf("source %q: %s %+v", src, o.Status, o.Evidence)
			}
		}
	})
	t.Run("socket in binds and mounts is one reason, several sockets are all named", func(t *testing.T) {
		o := run1(inspectDoc(ids, func(_ int, c map[string]any) {
			hostConfig(c)["Binds"] = []any{"/var/run/docker.sock:/a", "/run/docker.sock:/b"}
			c["Mounts"] = []any{map[string]any{"Source": "/var/run/docker.sock"}, map[string]any{"Source": "/run/docker.sock"}}
		}), 0, "")
		wantStatus(t, o, result.Fail)
		if o.Evidence[0].Detail != "docker socket mounted (/run/docker.sock); docker socket mounted (/var/run/docker.sock)" {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
	})
	t.Run("missing fields are an error, never clean", func(t *testing.T) {
		for name, mut := range map[string]func(int, map[string]any){
			"no HostConfig":   func(_ int, c map[string]any) { delete(c, "HostConfig") },
			"null HostConfig": func(_ int, c map[string]any) { c["HostConfig"] = nil },
			"no Privileged":   func(_ int, c map[string]any) { delete(hostConfig(c), "Privileged") },
			"no PidMode":      func(_ int, c map[string]any) { delete(hostConfig(c), "PidMode") },
			"no NetworkMode":  func(_ int, c map[string]any) { delete(hostConfig(c), "NetworkMode") },
			"short id":        func(_ int, c map[string]any) { c["Id"] = "abc" },
		} {
			o := run1(inspectDoc(ids, mut), 0, "")
			if o.Status != result.Error {
				t.Errorf("%s: %s (%s)", name, o.Status, o.Summary)
			}
		}
	})
	t.Run("output that is not what was asked for", func(t *testing.T) {
		other := idsN(2)[1]
		for name, doc := range map[string]string{
			"empty":          "",
			"not json":       "boom",
			"object":         `{"Id": "x"}`,
			"empty array":    "[]",
			"other id":       inspectDoc([]string{other}, nil),
			"id twice":       inspectDoc([]string{ids[0], ids[0]}, nil),
			"trailing data":  inspectDoc(ids, nil) + "[]",
			"array of nulls": "[null]",
		} {
			o := run1(doc, 0, "")
			if o.Status != result.Error {
				t.Errorf("%s: %s (%s)", name, o.Status, o.Summary)
			}
		}
		if o := run1(inspectDoc([]string{ids[0], ids[0]}, nil), 0, ""); !strings.Contains(o.Summary, "not asked for") {
			t.Errorf("a repeated container: %q", o.Summary)
		}
	})
	t.Run("exit status 1", func(t *testing.T) {
		gone := "Error response from daemon: No such container: " + ids[0] + "\n"
		o := run1("[]", 1, gone)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "1 container(s) stopped")
		for name, stderr := range map[string]string{
			"other message": "Error response from daemon: boom\n",
			"empty":         "",
			"mixed":         gone + "Error response from daemon: boom\n",
			"other id":      "Error response from daemon: No such container: " + idsN(2)[1] + "\n",
			"short id":      "Error response from daemon: No such container: abc\n",
		} {
			if o := run1("[]", 1, stderr); o.Status != result.Error {
				t.Errorf("%s: %s (%s)", name, o.Status, o.Summary)
			}
		}
		// a clean-looking document does not rescue a failing inspect
		if o := run1(inspectDoc(ids, nil), 2, ""); o.Status != result.Error {
			t.Errorf("exit 2: %s", o.Status)
		}
		if o := run1(inspectDoc(ids, nil), 1, "boom\n"); o.Status != result.Error {
			t.Errorf("exit 1 with another message: %s", o.Status)
		}
	})
	t.Run("fewer containers than asked for with exit 0", func(t *testing.T) {
		two := idsN(2)
		r := newRunner().AddResult(dockerPs, psOut(two)).AddResult(inspectArgv(two...), inline(inspectDoc(two[:1], nil), 0))
		wantStatus(t, exec(dockerProbe(t), r, probestest.FakeFS{}), result.Error)
	})
}

func TestDockerContainerNamesAreSanitised(t *testing.T) {
	ids := idsN(3)
	names := []string{"/web-1", "/evil\nname\x1b[31m with spaces", "/" + strings.Repeat("a", 300)}
	r := newRunner().AddResult(dockerPs, psOut(ids)).AddResult(inspectArgv(ids...), inline(inspectDoc(ids, func(i int, c map[string]any) {
		c["Name"] = names[i]
		hostConfig(c)["Privileged"] = true
	}), 0))
	o := exec(dockerProbe(t), r, probestest.FakeFS{})
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 3 {
		t.Fatalf("evidence %+v", o.Evidence)
	}
	bySubject := map[string]string{}
	for _, e := range o.Evidence {
		bySubject[e.Subject] = e.Detail
		if strings.ContainsAny(e.Subject+e.Detail, "\n\x1b") {
			t.Fatalf("control character in %+v", e)
		}
	}
	if _, ok := bySubject["web-1"]; !ok {
		t.Fatalf("subjects %v", subjects(o))
	}
	for _, id := range ids[1:] {
		d, ok := bySubject["id:"+id[:12]]
		if !ok || !strings.Contains(d, "name \"") || !strings.HasSuffix(d, "privileged") || len(d) > 120 {
			t.Fatalf("subject for %s: %v", id[:12], subjects(o))
		}
	}
}

func TestDockerBoundsAndChunks(t *testing.T) {
	t.Run("chunks of 25", func(t *testing.T) {
		ids := idsN(30)
		r := newRunner().AddResult(dockerPs, psOut(ids)).
			AddResult(inspectArgv(ids[:25]...), inline(inspectDoc(ids[:25], nil), 0)).
			AddResult(inspectArgv(ids[25:]...), inline(inspectDoc(ids[25:], func(_ int, c map[string]any) { hostConfig(c)["Privileged"] = true }), 0))
		o := exec(dockerProbe(t), r, probestest.FakeFS{})
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 5 {
			t.Fatalf("evidence %d", len(o.Evidence))
		}
		inspects := 0
		for _, c := range r.Calls() {
			if c.Argv[1] == "inspect" {
				inspects++
				if c.Opts.MaxOutput < 8<<20 {
					t.Errorf("inspect output limit %d is too small for large containers", c.Opts.MaxOutput)
				}
			}
		}
		if inspects != 2 {
			t.Fatalf("%d inspect calls", inspects)
		}
	})
	t.Run("more than 500 containers is partial", func(t *testing.T) {
		ids := idsN(501)
		r := newRunner().AddResult(dockerPs, psOut(ids))
		for i := 0; i < 500; i += 25 {
			chunk := ids[i : i+25]
			r.AddResult(inspectArgv(chunk...), inline(inspectDoc(chunk, func(j int, c map[string]any) {
				if i == 0 && j == 0 {
					hostConfig(c)["Privileged"] = true
				}
			}), 0))
		}
		o := exec(dockerProbe(t), r, probestest.FakeFS{})
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "only the first 500 were examined")
		wantSummary(t, o, "partial")
		if !eq(subjects(o), []string{"c000"}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("exactly 500 is fine", func(t *testing.T) {
		ids := idsN(500)
		r := newRunner().AddResult(dockerPs, psOut(ids))
		for i := 0; i < 500; i += 25 {
			r.AddResult(inspectArgv(ids[i:i+25]...), inline(inspectDoc(ids[i:i+25], nil), 0))
		}
		wantStatus(t, exec(dockerProbe(t), r, probestest.FakeFS{}), result.Pass)
	})
	t.Run("evidence is limited", func(t *testing.T) {
		ids := idsN(150)
		r := newRunner().AddResult(dockerPs, psOut(ids))
		for i := 0; i < 150; i += 25 {
			r.AddResult(inspectArgv(ids[i:i+25]...), inline(inspectDoc(ids[i:i+25], func(_ int, c map[string]any) { hostConfig(c)["Privileged"] = true }), 0))
		}
		o := exec(dockerProbe(t), r, probestest.FakeFS{})
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 100 || o.Evidence[99].Subject != "(51 more not shown)" {
			t.Fatalf("%d items, last %+v", len(o.Evidence), o.Evidence[len(o.Evidence)-1])
		}
		wantSummary(t, o, "and 51 more")
	})
}

func TestDockerPsOutput(t *testing.T) {
	for name, out := range map[string]string{
		"a name instead of an id": "web-1\n",
		"short id":                strings.Repeat("a", 12) + "\n",
		"upper case":              fmt.Sprintf("%064X", 255) + "\n",
		"id with a suffix":        idsN(1)[0] + " x\n",
		"an option":               "--all\n",
	} {
		t.Run(name, func(t *testing.T) {
			o := exec(dockerProbe(t), newRunner().AddResult(dockerPs, inline(out, 0)), probestest.FakeFS{})
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "not a container id")
		})
	}
	t.Run("exit status 1 with an id on stdout", func(t *testing.T) {
		o := exec(dockerProbe(t), newRunner().AddResult(dockerPs, inline(idsN(1)[0]+"\n", 1)), probestest.FakeFS{})
		wantStatus(t, o, result.Error)
	})
	t.Run("no containers", func(t *testing.T) {
		o := exec(dockerProbe(t), newRunner().AddResult(dockerPs, inline("", 0)), probestest.FakeFS{})
		wantStatus(t, o, result.Pass)
	})
}

func TestDockerCommonFailures(t *testing.T) {
	commonFailures(t, dockerProbe(t), dockerPs, "docker", probestest.FakeFS{})
}

func TestDockerCommonFailuresOfInspect(t *testing.T) {
	ids := idsN(1)
	for name, res := range map[string]execx.Result{
		"truncated": {Stdout: []byte(inspectDoc(ids, nil)), Truncated: true},
		"signaled":  {Stdout: []byte(inspectDoc(ids, nil)), Signaled: true, ExitCode: -1},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunner().AddResult(dockerPs, psOut(ids)).AddResult(inspectArgv(ids...), res)
			wantStatus(t, exec(dockerProbe(t), r, probestest.FakeFS{}), result.Error)
		})
	}
	for name, err := range map[string]error{"timeout": execx.ErrTimeout, "not allowlisted": execx.ErrNotAllowed, "missing": execx.ErrNotFound} {
		t.Run(name, func(t *testing.T) {
			r := newRunner().AddResult(dockerPs, psOut(ids)).AddError(inspectArgv(ids...), err)
			// docker vanishing between the two commands is an error too
			if o := exec(dockerProbe(t), r, probestest.FakeFS{}); o.Status != result.Error && o.Status != result.Skipped {
				t.Fatalf("status %s", o.Status)
			}
		})
	}
}

func TestDockerPrepareTakesNoParameters(t *testing.T) {
	prepareErr(t, "docker_exposure", map[string]any{"x": 1})
}

func TestDockerArgvIsFixed(t *testing.T) {
	ids := idsN(2)
	r := newRunner().AddResult(dockerPs, psOut(ids)).AddResult(inspectArgv(ids...), inline(inspectDoc(ids, nil), 0))
	exec(dockerProbe(t), r, probestest.FakeFS{})
	var got []string
	for _, c := range r.Calls() {
		got = append(got, strings.Join(c.Argv, " "))
	}
	want := []string{"docker ps -q --no-trunc", "docker inspect --type container -- " + ids[0] + " " + ids[1]}
	if !eq(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
}

// dockerd reads its flags with pflag, which lets single-dash letters be
// combined: "-DH tcp://..." is -D and -H. The expected results were checked
// against a real dockerd (see the notes of the task), not only against this
// reading of pflag.
func TestDockerCommandLineShorthandGroups(t *testing.T) {
	none := newRunner().AddResult(dockerPs, inline("", 0))
	cmd := func(args ...string) string { return "/usr/bin/dockerd\x00" + strings.Join(args, "\x00") + "\x00" }
	const tcp = "tcp://192.0.2.1:2375"
	cases := []struct {
		name string
		args []string
		want result.Status
		sub  string
	}{
		{"-DH separate value", []string{"-DH", tcp}, result.Fail, "dockerd " + tcp},
		{"-DH with attached value", []string{"-DH" + tcp}, result.Fail, "dockerd " + tcp},
		{"-DH= value", []string{"-DH=" + tcp}, result.Fail, "dockerd " + tcp},
		{"switches before and a value taker after", []string{"-Dv", "-DvH", tcp}, result.Fail, "dockerd " + tcp},
		{"another value taker before H in a group is its value", []string{"-sH", tcp}, result.Pass, ""},
		{"-p takes the rest of the group", []string{"-pH" + tcp}, result.Pass, ""},
		{"-G separate then -H", []string{"-G", "docker", "-H", tcp}, result.Fail, "dockerd " + tcp},
		{"-b with attached value then -DH", []string{"-bbr0", "-DH", tcp}, result.Fail, "dockerd " + tcp},
		{"-DH at the end has no value", []string{"-DH"}, result.Error, "-H without a value"},
		{"-D alone", []string{"-D"}, result.Pass, ""},
		{"a value taker takes the next argument even if it looks like a flag", []string{"-b", "-H" + tcp}, result.Pass, ""},
		{"-b separate then a real -H", []string{"-b", "br0", "-H", tcp}, result.Fail, "dockerd " + tcp},
		{"a switch with =value is not a host", []string{"-v=H", "-D=Htcp"}, result.Pass, ""},
		{"-D=false then -H", []string{"-D=false", "-H", tcp}, result.Fail, "dockerd " + tcp},
		{"-vh", []string{"-vh"}, result.Pass, ""},
		{"unix host in a group", []string{"-DH", "unix:///var/run/docker.sock"}, result.Pass, ""},
		{"unknown scheme in a group", []string{"-DH", "gopher://x"}, result.Error, "not understood"},
		{"an unknown letter before H: cannot be read", []string{"-xH", tcp}, result.Error, "cannot be read"},
		{"letters after H are its value", []string{"-Hx", tcp}, result.Fail, "dockerd x"},
		{"an unknown letter, no H in the group", []string{"-xyz", "-H", tcp}, result.Fail, "dockerd " + tcp},
		{"a lone dash is not a flag", []string{"-", "-H", tcp}, result.Fail, "dockerd " + tcp},
		{"tls=false then tlsverify", []string{"--tls=false", "--tlsverify", "-DH", tcp}, result.Fail, "tlsverify on"},
		{"tlsverify=false", []string{"--tlsverify=false", "-H", tcp}, result.Fail, "no TLS"},
		{"tls=false after tls", []string{"--tls", "--tls=false", "-H", tcp}, result.Fail, "no TLS"},
		{"tls with a value that is not a bool", []string{"--tls=maybe", "-H", tcp}, result.Error, "not understood"},
		{"--host= in a mix", []string{"-D", "--host=" + tcp}, result.Fail, "dockerd " + tcp},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := exec(dockerProbe(t), none, dockerHost("", cmd(c.args...)))
			wantStatus(t, o, c.want)
			if c.sub != "" && !strings.Contains(allText(o), c.sub) {
				t.Fatalf("%q lacks %q", allText(o), c.sub)
			}
		})
	}
}
