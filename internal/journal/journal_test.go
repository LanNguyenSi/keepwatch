package journal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

func cursor(i string) string {
	return "s=00000000000000000000000000000001;i=" + i + ";b=11111111111111111111111111111111;m=1;t=1;x=1"
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

func ts(us int64) time.Time { return time.UnixMicro(us).UTC() }

func TestDecodeFixtures(t *testing.T) {
	tests := []struct {
		name string
		want event.Event
	}{
		{"sshd_failed_password", event.Event{Kind: event.KindJournal, Cursor: cursor("1"), Time: ts(1760000000123456), UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", PID: 812, Priority: 6, Transport: "syslog", Comm: "sshd", Message: "Failed password for root from 203.0.113.7 port 51234 ssh2"}},
		{"sshd_invalid_user", event.Event{Kind: event.KindJournal, Cursor: cursor("2"), Time: ts(1760000001000000), UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", PID: 813, Priority: 6, Transport: "syslog", Comm: "sshd", Message: "Invalid user admin from 203.0.113.7 port 51240"}},
		{"sshd_accepted_publickey", event.Event{Kind: event.KindJournal, Cursor: cursor("3"), Time: ts(1760000002000000), UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", PID: 814, Priority: 6, Transport: "syslog", Comm: "sshd", Message: "Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2: ED25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg"}},
		{"sshd_accepted_password", event.Event{Kind: event.KindJournal, Cursor: cursor("4"), Time: ts(1760000003000000), UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", PID: 815, Priority: 6, Transport: "syslog", Comm: "sshd", Message: "Accepted password for deploy from 198.51.100.4 port 40030 ssh2"}},
		{"systemd_restart", event.Event{Kind: event.KindJournal, Cursor: cursor("5"), Time: ts(1760000004000000), UID: 0, SystemdUnit: "init.scope", Unit: "nginx.service", Identifier: "systemd", PID: 1, Priority: 6, Transport: "journal", Comm: "systemd", Message: "nginx.service: Scheduled restart job, restart counter is at 3."}},
		{"systemd_exit", event.Event{Kind: event.KindJournal, Cursor: cursor("6"), Time: ts(1760000005000000), UID: 0, SystemdUnit: "init.scope", Unit: "nginx.service", Identifier: "systemd", PID: 1, Priority: 5, Transport: "journal", Comm: "systemd", ExitCode: "exited", ExitStatus: "1", Message: "nginx.service: Main process exited, code=exited, status=1/FAILURE"}},
		{"systemd_result", event.Event{Kind: event.KindJournal, Cursor: cursor("13"), Time: ts(1760000005100000), UID: 0, SystemdUnit: "init.scope", Unit: "nginx.service", Identifier: "systemd", PID: 1, Priority: 4, Transport: "journal", Comm: "systemd", UnitResult: "exit-code", Message: "nginx.service: Failed with result 'exit-code'."}},
		{"kernel_oom", event.Event{Kind: event.KindJournal, Cursor: cursor("7"), Time: ts(1760000006000000), UID: -1, Identifier: "kernel", Priority: 3, Transport: "kernel", Message: "Out of memory: Killed process 4242 (java) total-vm:8388608kB, anon-rss:4194304kB, file-rss:0kB, shmem-rss:0kB, UID:1001 pgtables:9000kB oom_score_adj:0"}},
		// Absent _UID and PRIORITY are -1, never 0.
		{"kernel_no_uid_no_priority", event.Event{Kind: event.KindJournal, Cursor: cursor("8"), Time: ts(1760000007000000), UID: -1, Identifier: "kernel", Priority: -1, Transport: "kernel", Message: "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/,task=java,pid=4242,uid=1001"}},
		// Explicit null behaves like absent.
		{"null_uid_priority", event.Event{Kind: event.KindJournal, Cursor: cursor("9"), Time: ts(1760000008000000), UID: -1, Priority: -1, Transport: "kernel", Message: "hello"}},
		// Syslog forgery: a user process (UID 1000, session scope) logs as
		// sshd. The trusted fields show it.
		{"forged_sshd_syslog", event.Event{Kind: event.KindJournal, Cursor: cursor("10"), Time: ts(1760000009000000), UID: 1000, SystemdUnit: "session-3.scope", Identifier: "sshd", PID: 9001, Priority: 6, Transport: "syslog", Comm: "logger", Message: "Failed password for root from 203.0.113.99 port 22 ssh2"}},
		// Native forgery: a user process names another unit in UNIT.
		{"forged_unit_native", event.Event{Kind: event.KindJournal, Cursor: cursor("14"), Time: ts(1760000009500000), UID: 1000, SystemdUnit: "session-3.scope", Unit: "nginx.service", Identifier: "systemd", PID: 9002, Priority: 4, Transport: "journal", Comm: "python3", UnitResult: "oom-kill", Message: "nginx.service: Failed with result 'oom-kill'."}},
		// A field that occurs several times: the first value wins.
		{"multi_unit", event.Event{Kind: event.KindJournal, Cursor: cursor("15"), Time: ts(1760000013000000), UID: 1000, Unit: "a.service", Identifier: "app", Priority: 6, Transport: "journal", Message: "x"}},
		{"multi_message", event.Event{Kind: event.KindJournal, Cursor: cursor("16"), Time: ts(1760000014000000), UID: 1000, Identifier: "app", Priority: 6, Transport: "journal", Message: "a\xffb"}},
		{"multi_message_string_first", event.Event{Kind: event.KindJournal, Cursor: cursor("17"), Time: ts(1760000015000000), UID: 1000, Identifier: "app", Priority: 6, Transport: "journal", Message: "first"}},
		// Sender-set PRIORITY that is not a number or outside 0..7 is -1.
		{"priority_high", event.Event{Kind: event.KindJournal, Cursor: cursor("18"), Time: ts(1760000016000000), UID: 1000, Identifier: "app", Priority: -1, Transport: "journal", Message: "p"}},
		{"priority_space6", event.Event{Kind: event.KindJournal, Cursor: cursor("18"), Time: ts(1760000016000000), UID: 1000, Identifier: "app", Priority: -1, Transport: "journal", Message: "p"}},
		{"priority_99", event.Event{Kind: event.KindJournal, Cursor: cursor("18"), Time: ts(1760000016000000), UID: 1000, Identifier: "app", Priority: -1, Transport: "journal", Message: "p"}},
		// journalctl emits a field of 4096 bytes or more as null.
		{"null_message", event.Event{Kind: event.KindJournal, Cursor: cursor("19"), Time: ts(1760000017000000), UID: 1000, Identifier: "app", Priority: 6, Transport: "journal"}},
		// journalctl emits a MESSAGE with a newline and ESC as a byte array.
		{"hostile_user_escape", event.Event{Kind: event.KindJournal, Cursor: cursor("11"), Time: ts(1760000010000000), UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", PID: 816, Priority: 6, Transport: "syslog", Comm: "sshd", Message: "Invalid user evil\n\x1b[31mRED\x1b[0m from 203.0.113.7 port 1"}},
		// A JSON string with a newline arrives unchanged too.
		{"hostile_user_newline", event.Event{Kind: event.KindJournal, Cursor: cursor("20"), Time: ts(1760000010000000), UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", PID: 816, Priority: 6, Transport: "syslog", Comm: "sshd", Message: "Invalid user evil\nbob from 203.0.113.7 port 1"}},
		// Byte-array MESSAGE: raw bytes, including invalid UTF-8.
		{"bytearray_message", event.Event{Kind: event.KindJournal, Cursor: cursor("12"), Time: ts(1760000011000000), UID: 1000, Identifier: "app", Priority: -1, Transport: "syslog", Message: "bytes \xff\xfe ok"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(fixture(t, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got  %#v\nwant %#v", got, tc.want)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, tc := range []struct{ name, line, cursor string }{
		{"no_cursor", string(fixture(t, "no_cursor")), ""},
		{"bad_pid", string(fixture(t, "bad_pid")), "c"},
		{"empty cursor", `{"__CURSOR":"","MESSAGE":"x"}`, ""},
		{"null cursor", `{"__CURSOR":null,"MESSAGE":"x"}`, ""},
		{"bad timestamp", `{"__CURSOR":"c","__REALTIME_TIMESTAMP":"yesterday"}`, "c"},
		{"bad uid", `{"__CURSOR":"c","_UID":"-x"}`, "c"},
		{"uid array", `{"__CURSOR":"c","_UID":["0","1000"]}`, "c"},
		{"uid byte array", `{"__CURSOR":"c","_UID":[48]}`, "c"},
		{"pid array", `{"__CURSOR":"c","_PID":["1","2"]}`, "c"},
		{"unit array", `{"__CURSOR":"c","_SYSTEMD_UNIT":["ssh.service","x.service"]}`, "c"},
		{"unit byte array", `{"__CURSOR":"c","_SYSTEMD_UNIT":[115]}`, "c"},
		{"transport array", `{"__CURSOR":"c","_TRANSPORT":["kernel","syslog"]}`, "c"},
		{"timestamp array", `{"__CURSOR":"c","__REALTIME_TIMESTAMP":["1","2"]}`, "c"},
		{"uid number", `{"__CURSOR":"c","_UID":0}`, "c"},
		{"cursor array", `{"__CURSOR":["a","b"]}`, ""},
		{"not an object", `["x"]`, ""},
		{"empty", ``, ""},
		{"truncated", `{"__CURSOR":"c","MESSAGE":"x`, ""},
		{"trailing data", `{"__CURSOR":"c"} {}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := Decode([]byte(tc.line))
			if err == nil {
				t.Fatalf("want error, got %#v", ev)
			}
			var le *LineError
			if !errors.As(err, &le) {
				t.Fatalf("error %T is not a *LineError", err)
			}
			if le.Cursor != tc.cursor {
				t.Fatalf("cursor %q, want %q", le.Cursor, tc.cursor)
			}
		})
	}
}

// Problems in sender-set fields are data, not errors.
func TestDecodeSenderFieldsAreSoft(t *testing.T) {
	for _, line := range []string{
		`{"__CURSOR":"c","MESSAGE":[256]}`,
		`{"__CURSOR":"c","MESSAGE":5}`,
		`{"__CURSOR":"c","MESSAGE":[]}`,
		`{"__CURSOR":"c","MESSAGE":[[1,[2]],"x"]}`,
		`{"__CURSOR":"c","UNIT":{"a":1},"PRIORITY":[[1]],"EXIT_CODE":true}`,
		`{"__CURSOR":"c","PRIORITY":"-1"}`,
		`{"__CURSOR":"c","PRIORITY":"-5"}`,
		`{"__CURSOR":"c","PRIORITY":"+3"}`,
		`{"__CURSOR":"c","PRIORITY":"03"}`,
		`{"__CURSOR":"c","PRIORITY":"8"}`,
		`{"__CURSOR":"c","PRIORITY":"-"}`,
		`{"__CURSOR":"c","PRIORITY":"/"}`,
		`{"__CURSOR":"c","MESSAGE":[null,"small"]}`,
	} {
		ev, err := Decode([]byte(line))
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if ev.Cursor != "c" || ev.Message != "" || ev.Priority != -1 {
			t.Fatalf("%s: %#v", line, ev)
		}
	}
	for p := 0; p <= 7; p++ {
		ev, err := Decode([]byte(`{"__CURSOR":"c","PRIORITY":"` + string(rune('0'+p)) + `"}`))
		if err != nil || ev.Priority != p {
			t.Fatalf("priority %d: %#v %v", p, ev, err)
		}
	}
	// An escaped quote inside the first value of a multi-value field.
	ev, err := Decode([]byte(`{"__CURSOR":"c","MESSAGE":["a\"b","c"]}`))
	if err != nil || ev.Message != `a"b` {
		t.Fatalf("escaped quote: %#v %v", ev, err)
	}
}

// Decoding allocates about the size of the line, also for byte arrays.
func TestDecodeAllocationBound(t *testing.T) {
	const n = 1 << 20
	var arr strings.Builder
	arr.WriteString(`{"__CURSOR":"c","MESSAGE":[`)
	for i := 0; i < n/2; i++ {
		if i > 0 {
			arr.WriteByte(',')
		}
		arr.WriteByte('7')
	}
	arr.WriteString(`]}`)
	lines := map[string][]byte{
		"byte array": []byte(arr.String()),
		"string":     []byte(`{"__CURSOR":"c","MESSAGE":"` + strings.Repeat("a", n) + `"}`),
	}
	for name, line := range lines {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		ev, err := Decode(line)
		runtime.ReadMemStats(&after)
		if err != nil || len(ev.Message) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		if got, limit := after.TotalAlloc-before.TotalAlloc, uint64(len(line))*5/4; got > limit {
			t.Fatalf("%s: allocated %d bytes for a %d byte line (limit %d)", name, got, len(line), limit)
		}
	}
}

func TestDecodeMissingFieldsAreEmpty(t *testing.T) {
	got, err := Decode([]byte(`{"__CURSOR":"c"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := event.Event{Kind: event.KindJournal, Cursor: "c", UID: -1, Priority: -1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestDecodeIgnoresUnknownFields(t *testing.T) {
	got, err := Decode([]byte(`{"__CURSOR":"c","_HOSTNAME":"h","FOO":[1,2,3],"BAR":{"x":1},"MESSAGE":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Message != "m" || got.Cursor != "c" {
		t.Fatalf("got %#v", got)
	}
}

func TestDecodeLargeMessage(t *testing.T) {
	msg := strings.Repeat("a", 1<<20)
	got, err := Decode([]byte(`{"__CURSOR":"c","MESSAGE":"` + msg + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Message != msg {
		t.Fatalf("message length %d, want %d", len(got.Message), len(msg))
	}
	// The same size as a byte array.
	var b strings.Builder
	b.WriteString(`{"__CURSOR":"c","MESSAGE":[`)
	for i := 0; i < 1<<20; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("97")
	}
	b.WriteString(`]}`)
	got, err = Decode([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Message != msg {
		t.Fatalf("byte array message length %d, want %d", len(got.Message), len(msg))
	}
}

func FuzzDecode(f *testing.F) {
	for _, name := range []string{"sshd_failed_password", "forged_sshd_syslog", "forged_unit_native", "hostile_user_escape", "hostile_user_newline", "bytearray_message", "no_cursor", "bad_pid", "null_uid_priority", "systemd_exit", "systemd_result", "multi_unit", "multi_message", "multi_message_string_first", "priority_high", "priority_99", "null_message"} {
		b, err := os.ReadFile(filepath.Join("testdata", name+".json"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"__CURSOR":"c","MESSAGE":[1,2,300]}`))
	f.Add([]byte(`{"__CURSOR":"c","MESSAGE":[[1]]}`))
	f.Add([]byte(`{"__CURSOR":"c","MESSAGE":[[1,2],"x"]}`))
	f.Add([]byte(`{"__CURSOR":"c","MESSAGE":["a\\"]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"__CURSOR":"c","__REALTIME_TIMESTAMP":"9223372036854775807"}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		ev, err := Decode(line)
		var le *LineError
		if err != nil && !errors.As(err, &le) {
			t.Fatalf("error %T is not a *LineError", err)
		}
		if err == nil && ev.Cursor == "" {
			t.Fatalf("accepted a line with an empty cursor: %q", line)
		}
	})
}

func TestArgs(t *testing.T) {
	base := []string{"--output=json", "--follow", "--no-pager"}
	got, err := Args("")
	if err != nil || !reflect.DeepEqual(got, append(append([]string{}, base...), "--lines=0")) {
		t.Fatalf("empty cursor: %v %v", got, err)
	}
	c := cursor("1")
	got, err = Args(c)
	if err != nil || !reflect.DeepEqual(got, append(append([]string{}, base...), "--after-cursor="+c)) {
		t.Fatalf("cursor: %v %v", got, err)
	}
	// A cursor with shell metacharacters stays one element.
	odd := "s=1;i=$(x) `y` 'z' \"q\" *"
	got, err = Args(odd)
	if err != nil || len(got) != 4 || got[3] != "--after-cursor="+odd {
		t.Fatalf("odd cursor: %v %v", got, err)
	}
	for _, bad := range []string{"a\nb", "a\x00b", "\n"} {
		if got, err := Args(bad); err == nil {
			t.Fatalf("cursor %q accepted: %v", bad, got)
		}
	}
}
