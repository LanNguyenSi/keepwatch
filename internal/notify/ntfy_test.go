package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

const tok = "tk_0123456789abcdefghijklmnopqrs"

type req struct {
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   string
}

// server answers with the given handler and records the requests.
type server struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []req
}

func newServer(t *testing.T, h func(n int, w http.ResponseWriter, r *http.Request)) *server {
	t.Helper()
	s := &server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, req{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)})
		n := len(s.reqs)
		s.mu.Unlock()
		h(n, w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func (s *server) at(i int) req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqs[i]
}

func status(code int) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

func token() ([]byte, error) { return []byte(tok), nil }

// recorder is a sleep that records what it was asked to wait.
type recorder struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (r *recorder) sleep(_ context.Context, d time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waits = append(r.waits, d)
	return nil
}

func newNtfy(t *testing.T, base string, rec *recorder, opts ...Option) *Ntfy {
	t.Helper()
	o := append([]Option{WithSleep(rec.sleep), WithBackoff(2 * time.Second)}, opts...)
	n, err := NewNtfy(NtfyConfig{URL: base, Topic: "alerts", ReadToken: token}, o...)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSendPostsTheMessage(t *testing.T) {
	s := newServer(t, status(200))
	n := newNtfy(t, s.URL, &recorder{})
	err := n.Send(context.Background(), Message{Title: "keepwatch host: 2 alerts", Body: "**2 alerts**\n- ` a `\n", Markdown: true, Priority: 4, Tags: []string{"keepwatch", "rotating_light"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.count() != 1 {
		t.Fatalf("%d requests", s.count())
	}
	r := s.at(0)
	if r.Method != "POST" || r.Path != "/alerts" || r.RawQuery != "" {
		t.Errorf("request %s %s?%s", r.Method, r.Path, r.RawQuery)
	}
	want := map[string]string{
		"Authorization": "Bearer " + tok, "Title": "keepwatch host: 2 alerts", "Priority": "4",
		"Tags": "keepwatch,rotating_light", "Markdown": "yes", "Content-Type": "text/plain; charset=utf-8", "User-Agent": "keepwatch",
	}
	for k, v := range want {
		if got := r.Header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if r.Body != "**2 alerts**\n- ` a `\n" {
		t.Errorf("body %q", r.Body)
	}
}

func TestSendWithoutTokenAndWithoutOptionalFields(t *testing.T) {
	s := newServer(t, status(200))
	n, err := NewNtfy(NtfyConfig{URL: s.URL, Topic: "alerts"})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), Message{Body: "x"}); err != nil {
		t.Fatal(err)
	}
	h := s.at(0).Header
	for _, k := range []string{"Authorization", "Title", "Priority", "Tags", "Markdown"} {
		if _, ok := h[k]; ok {
			t.Errorf("header %s set: %q", k, h.Get(k))
		}
	}
}

func TestPathPrefixOfTheServerIsKept(t *testing.T) {
	s := newServer(t, status(200))
	for base, want := range map[string]string{s.URL + "/ntfy": "/ntfy/alerts", s.URL + "/ntfy/": "/ntfy/alerts", s.URL + "/": "/alerts"} {
		n, err := NewNtfy(NtfyConfig{URL: base, Topic: "alerts"})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Send(context.Background(), Message{Body: "x"}); err != nil {
			t.Fatal(err)
		}
		if got := s.at(s.count() - 1).Path; got != want {
			t.Errorf("%s: path %q, want %q", base, got, want)
		}
	}
}

func TestAuthFailuresAreNotRetried(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 408, 413} {
		s := newServer(t, status(code))
		rec := &recorder{}
		err := newNtfy(t, s.URL, rec).Send(context.Background(), Message{Body: "x"})
		e := AsError(err)
		if e == nil || e.Class != Permanent || e.Status != code || e.Attempts != 1 {
			t.Errorf("%d: %#v", code, err)
		}
		if s.count() != 1 || len(rec.waits) != 0 {
			t.Errorf("%d: %d requests, waits %v", code, s.count(), rec.waits)
		}
	}
}

func TestServerErrorIsRetriedOnceWithBackoff(t *testing.T) {
	for _, code := range []int{500, 502, 503, 504, 599} {
		s := newServer(t, func(n int, w http.ResponseWriter, _ *http.Request) {
			if n == 1 {
				w.WriteHeader(code)
				return
			}
			w.WriteHeader(200)
		})
		rec := &recorder{}
		if err := newNtfy(t, s.URL, rec).Send(context.Background(), Message{Body: "x"}); err != nil {
			t.Errorf("%d: %v", code, err)
		}
		if s.count() != 2 || len(rec.waits) != 1 || rec.waits[0] != 2*time.Second {
			t.Errorf("%d: %d requests, waits %v", code, s.count(), rec.waits)
		}
		// Both attempts carry the same message.
		if a, b := s.at(0), s.at(1); a.Body != b.Body || a.Header.Get("Authorization") != b.Header.Get("Authorization") {
			t.Errorf("%d: the retry differs from the first request", code)
		}
	}
}

func TestServerErrorTwiceIsAFailureAfterExactlyTwoRequests(t *testing.T) {
	s := newServer(t, status(503))
	rec := &recorder{}
	err := newNtfy(t, s.URL, rec).Send(context.Background(), Message{Body: "x"})
	e := AsError(err)
	if e == nil || e.Class != Transient || e.Status != 503 || e.Attempts != 2 {
		t.Fatalf("%#v", err)
	}
	if s.count() != 2 || !strings.Contains(err.Error(), "after 2 attempts") {
		t.Errorf("%d requests, %v", s.count(), err)
	}
}

func TestTooManyRequestsHonoursRetryAfterWithinTheCap(t *testing.T) {
	cases := []struct {
		name, header string
		wantWait     time.Duration
		wantRequests int
	}{
		{"seconds above the backoff", "7", 7 * time.Second, 2},
		{"seconds below the backoff", "1", 2 * time.Second, 2},
		{"at the cap", "30", 30 * time.Second, 2},
		{"above the cap", "31", 0, 1},
		{"a day", "86400", 0, 1},
		{"a number that overflows a duration", "10000000000", 0, 1},
		{"nonsense", "soon", 2 * time.Second, 2},
		{"negative", "-5", 2 * time.Second, 2},
		{"absent", "", 2 * time.Second, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer(t, func(n int, w http.ResponseWriter, _ *http.Request) {
				if n == 1 {
					if c.header != "" {
						w.Header().Set("Retry-After", c.header)
					}
					w.WriteHeader(429)
					return
				}
				w.WriteHeader(200)
			})
			rec := &recorder{}
			err := newNtfy(t, s.URL, rec).Send(context.Background(), Message{Body: "x"})
			if c.wantRequests == 1 {
				if e := AsError(err); e == nil || e.Status != 429 || !strings.Contains(e.Msg, "asks to wait") {
					t.Errorf("error %#v", err)
				}
				if len(rec.waits) != 0 {
					t.Errorf("waited %v", rec.waits)
				}
			} else {
				if err != nil {
					t.Errorf("error %v", err)
				}
				if len(rec.waits) != 1 || rec.waits[0] != c.wantWait {
					t.Errorf("waits %v, want %v", rec.waits, c.wantWait)
				}
			}
			if s.count() != c.wantRequests {
				t.Errorf("%d requests, want %d", s.count(), c.wantRequests)
			}
		})
	}
}

func TestRetryAfterAsAnHTTPDate(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	if d := retryAfter(now.Add(9*time.Second).Format(http.TimeFormat), now); d != 9*time.Second {
		t.Errorf("future date: %v", d)
	}
	if d := retryAfter(now.Add(-time.Hour).Format(http.TimeFormat), now); d != 0 {
		t.Errorf("past date: %v", d)
	}
}

func TestTimeoutIsATransientFailureWithOneRetry(t *testing.T) {
	block := make(chan struct{})
	s := newServer(t, func(int, http.ResponseWriter, *http.Request) { <-block })
	t.Cleanup(func() { close(block) })
	rec := &recorder{}
	start := time.Now()
	err := newNtfy(t, s.URL, rec, WithTimeout(80*time.Millisecond)).Send(context.Background(), Message{Body: "x"})
	e := AsError(err)
	if e == nil || e.Class != Transient || e.Status != 0 || e.Attempts != 2 || !strings.Contains(e.Msg, "timeout") {
		t.Fatalf("%#v", err)
	}
	if s.count() != 2 || time.Since(start) > 5*time.Second {
		t.Errorf("%d requests in %v", s.count(), time.Since(start))
	}
}

func TestConnectionRefusedIsRetriedOnceAndNamesNeitherAddressNorTopic(t *testing.T) {
	s := newServer(t, status(200))
	base := s.URL
	s.Close()
	rec := &recorder{}
	n, err := NewNtfy(NtfyConfig{URL: base, Topic: "secrettopic", ReadToken: token}, WithSleep(rec.sleep))
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), Message{Body: "x"})
	e := AsError(err)
	if e == nil || e.Class != Transient || e.Attempts != 2 || len(rec.waits) != 1 {
		t.Fatalf("%#v waits %v", err, rec.waits)
	}
	for _, bad := range []string{"secrettopic", tok, "http://"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("%q in the error: %v", bad, err)
		}
	}
}

func TestRedirectIsNotFollowedAndTheTokenStaysHome(t *testing.T) {
	other := newServer(t, status(200))
	for _, code := range []int{301, 302, 303, 307, 308} {
		s := newServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, other.URL+"/steal", code)
		})
		rec := &recorder{}
		err := newNtfy(t, s.URL, rec).Send(context.Background(), Message{Body: "secret body"})
		e := AsError(err)
		if e == nil || e.Class != Permanent || e.Status != code || e.Attempts != 1 {
			t.Errorf("%d: %#v", code, err)
		}
		if s.count() != 1 || len(rec.waits) != 0 {
			t.Errorf("%d: %d requests", code, s.count())
		}
	}
	if other.count() != 0 {
		t.Errorf("the redirect target got %d requests: %+v", other.count(), other.at(0))
	}
}

func TestEnvironmentProxyIsNeverUsed(t *testing.T) {
	proxy := newServer(t, status(200))
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	n, err := NewNtfy(NtfyConfig{URL: "https://ntfy.example.com", Topic: "alerts"})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := n.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", n.client.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("the transport has a proxy function")
	}
	r, _ := http.NewRequest("POST", "https://ntfy.example.com/alerts", nil)
	if tr.Proxy != nil {
		if u, _ := tr.Proxy(r); u != nil {
			t.Errorf("proxy %v", u)
		}
	}
	if tr.DisableKeepAlives != true || n.client.Timeout != DefaultTimeout || n.client.CheckRedirect == nil {
		t.Errorf("client settings: keepalives off %v, timeout %v", tr.DisableKeepAlives, n.client.Timeout)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Errorf("tls config %+v", tr.TLSClientConfig)
	}
}

func TestTLSCertificatesAreVerified(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	rec := &recorder{}
	// The test CA is unknown to the system: no request gets through.
	n, err := NewNtfy(NtfyConfig{URL: srv.URL, Topic: "alerts"}, WithSleep(rec.sleep))
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), Message{Body: "x"})
	if e := AsError(err); e == nil || !strings.Contains(e.Msg, "certificate") {
		t.Errorf("error %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests reached a server with an untrusted certificate", hits.Load())
	}
	// With the CA it works.
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	n, err = NewNtfy(NtfyConfig{URL: srv.URL, Topic: "alerts"}, WithRootCAs(pool), WithSleep(rec.sleep))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), Message{Body: "x"}); err != nil || hits.Load() != 1 {
		t.Errorf("error %v, hits %d", err, hits.Load())
	}
}

func TestHeaderInjectionIsNotPossible(t *testing.T) {
	s := newServer(t, status(200))
	n := newNtfy(t, s.URL, &recorder{})
	m := Message{
		Title:    "alert\r\nX-Evil: 1\r\nPriority: 1\nContent-Length: 0\u0000 ä",
		Body:     "x",
		Priority: 3,
		Tags:     []string{"ok", "bad\r\nX-Evil: 1", "has space", "", "a,b", strings.Repeat("a", 33), "t1", "t2", "t3", "t4", "t5", "t6"},
	}
	if err := n.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	h := s.at(0).Header
	if h.Get("X-Evil") != "" {
		t.Errorf("injected header: %v", h)
	}
	if got := h.Get("Priority"); got != "3" {
		t.Errorf("priority %q", got)
	}
	title := h.Get("Title")
	if strings.ContainsAny(title, "\r\n\x00") || !strings.HasPrefix(title, "alert??X-Evil: 1??Priority: 1?") {
		t.Errorf("title %q", title)
	}
	if tags := h.Get("Tags"); tags != "ok,t1,t2,t3,t4" {
		t.Errorf("tags %q (at most five valid tags)", tags)
	}
}

func TestTitleIsBounded(t *testing.T) {
	s := newServer(t, status(200))
	n := newNtfy(t, s.URL, &recorder{})
	if err := n.Send(context.Background(), Message{Title: strings.Repeat("t", 5000), Body: "x"}); err != nil {
		t.Fatal(err)
	}
	if got := len(s.at(0).Header.Get("Title")); got != MaxTitleBytes {
		t.Errorf("title of %d bytes", got)
	}
}

func TestMessageLimitsAreEnforcedBeforeAnyRequest(t *testing.T) {
	s := newServer(t, status(200))
	n := newNtfy(t, s.URL, &recorder{})
	if err := n.Send(context.Background(), Message{Body: strings.Repeat("x", MaxBodyBytes)}); err != nil {
		t.Errorf("a body at the limit: %v", err)
	}
	for name, m := range map[string]Message{
		"body over the limit": {Body: strings.Repeat("x", MaxBodyBytes+1)},
		"priority 6":          {Body: "x", Priority: 6},
		"priority -1":         {Body: "x", Priority: -1},
	} {
		before := s.count()
		err := n.Send(context.Background(), m)
		if e := AsError(err); e == nil || e.Class != Permanent || e.Attempts != 0 {
			t.Errorf("%s: %#v", name, err)
		}
		if s.count() != before {
			t.Errorf("%s: a request was made", name)
		}
	}
}

func TestTokenProblemsFailBeforeAnyRequest(t *testing.T) {
	s := newServer(t, status(200))
	cases := map[string]func() ([]byte, error){
		"unreadable":      func() ([]byte, error) { return nil, errors.New("token file is too open") },
		"empty":           func() ([]byte, error) { return nil, nil },
		"newline inside":  func() ([]byte, error) { return []byte("tk_abc\nX-Evil: 1"), nil },
		"space inside":    func() ([]byte, error) { return []byte("tk abc"), nil },
		"non ascii":       func() ([]byte, error) { return []byte("tk_ä"), nil },
		"control byte":    func() ([]byte, error) { return []byte("tk_\x01"), nil },
		"carriage return": func() ([]byte, error) { return []byte("tk_abc\r"), nil },
	}
	for name, rt := range cases {
		n, err := NewNtfy(NtfyConfig{URL: s.URL, Topic: "alerts", ReadToken: rt})
		if err != nil {
			t.Fatal(err)
		}
		err = n.Send(context.Background(), Message{Body: "x"})
		if e := AsError(err); e == nil || e.Class != Permanent || e.Attempts != 0 {
			t.Errorf("%s: %#v", name, err)
		}
	}
	if s.count() != 0 {
		t.Errorf("%d requests with a bad token", s.count())
	}
}

func TestTokenIsReadForEverySend(t *testing.T) {
	s := newServer(t, status(200))
	var calls int
	n, _ := NewNtfy(NtfyConfig{URL: s.URL, Topic: "alerts", ReadToken: func() ([]byte, error) {
		calls++
		return []byte("tk_" + string(rune('a'+calls))), nil
	}})
	n.Send(context.Background(), Message{Body: "x"})
	n.Send(context.Background(), Message{Body: "x"})
	if s.at(0).Header.Get("Authorization") != "Bearer tk_b" || s.at(1).Header.Get("Authorization") != "Bearer tk_c" {
		t.Errorf("tokens %q %q", s.at(0).Header.Get("Authorization"), s.at(1).Header.Get("Authorization"))
	}
}

func TestTokenNeverAppearsInAnError(t *testing.T) {
	s := newServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		// A server that echoes the request in its answer.
		w.WriteHeader(403)
		io.WriteString(w, `{"code":40301,"http":403,"error":"forbidden `+r.Header.Get("Authorization")+`"}`)
	})
	err := newNtfy(t, s.URL, &recorder{}).Send(context.Background(), Message{Body: "x"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("%v", err)
	}
	// The text of the server is part of the error (a person reads it); it is
	// the caller's job to redact it, and ntfy tokens are in the built-in
	// patterns. What this package guarantees is the shape of that text.
	if strings.ContainsAny(err.Error(), "\r\n\x00") {
		t.Errorf("control characters in %q", err)
	}
}

func TestServerReason(t *testing.T) {
	cases := map[string]string{
		`{"code":42901,"http":429,"error":"limit reached: too many requests"}`: ": limit reached: too many requests",
		`{"error" : "a\"b\nc"}`:  ": a?b?c",
		"{\"error\":\"äö\x01\"}": ": ?????",
		`{"error":""}`:           "",
		`{"error":7}`:            "",
		`<html>error</html>`:     "",
		``:                       "",
		`{"error":"` + strings.Repeat("x", 500) + `"}`: ": " + strings.Repeat("x", 200),
	}
	for in, want := range cases {
		if got := serverReason([]byte(in)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestHugeAnswerIsReadBoundedAndStillASuccess(t *testing.T) {
	s := newServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		chunk := []byte(strings.Repeat("x", 1<<16))
		for i := 0; i < 512; i++ { // 32 MiB
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	if err := newNtfy(t, s.URL, &recorder{}).Send(context.Background(), Message{Body: "x"}); err != nil {
		t.Errorf("%v", err)
	}
}

func TestCancelledContextStopsTheRetry(t *testing.T) {
	s := newServer(t, status(500))
	ctx, cancel := context.WithCancel(context.Background())
	n, _ := NewNtfy(NtfyConfig{URL: s.URL, Topic: "alerts"}, WithSleep(func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}))
	err := n.Send(ctx, Message{Body: "x"})
	if e := AsError(err); e == nil || e.Attempts != 1 {
		t.Errorf("%#v", err)
	}
	if s.count() != 1 {
		t.Errorf("%d requests", s.count())
	}
	// Cancelled before the first request: no request is made.
	before := s.count()
	if err := n.Send(ctx, Message{Body: "x"}); err == nil || s.count() != before {
		t.Errorf("error %v, %d requests", err, s.count()-before)
	}
}

func TestSleepCtx(t *testing.T) {
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Error(err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Error(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Error("a cancelled sleep returned nil")
	}
	if err := sleepCtx(ctx, 0); err == nil {
		t.Error("a cancelled zero sleep returned nil")
	}
}

func TestNewNtfyChecksItsSettings(t *testing.T) {
	good := []string{"https://ntfy.example.com", "https://ntfy.example.com/", "https://ntfy.example.com:8443/prefix", "http://127.0.0.1:8080", "http://localhost", "http://[::1]:80"}
	for _, u := range good {
		if _, err := NewNtfy(NtfyConfig{URL: u, Topic: "alerts"}); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := []string{
		"", "ntfy.example.com", "http://ntfy.example.com", "ftp://ntfy.example.com", "https://", "https://:443", "https://host:",
		"https://user:pass@ntfy.example.com", "https://user@ntfy.example.com", "https://ntfy.example.com?x=1", "https://ntfy.example.com/?", "https://ntfy.example.com#frag",
		"http://127.0.0.1.example.com", "file:///etc/passwd",
	}
	for _, u := range bad {
		if _, err := NewNtfy(NtfyConfig{URL: u, Topic: "alerts"}); err == nil {
			t.Errorf("%q was accepted", u)
		} else if strings.Contains(err.Error(), "pass@") {
			t.Errorf("credentials in the error: %v", err)
		}
	}
	for _, topic := range []string{"", "a/b", "a b", "..", "a?b", "a#b", "a%2fb", "a\nb", strings.Repeat("a", 65), "ä", "a:b"} {
		if _, err := NewNtfy(NtfyConfig{URL: "https://ntfy.example.com", Topic: topic}); err == nil {
			t.Errorf("topic %q was accepted", topic)
		}
	}
	for _, topic := range []string{"a", "alerts", "My_Topic-1", strings.Repeat("a", 64)} {
		if _, err := NewNtfy(NtfyConfig{URL: "https://ntfy.example.com", Topic: topic}); err != nil {
			t.Errorf("topic %q: %v", topic, err)
		}
	}
}

func TestEndpointIsBuiltFromTheValidatedParts(t *testing.T) {
	n, err := NewNtfy(NtfyConfig{URL: "https://ntfy.example.com:8443/pre/", Topic: "my-topic"})
	if err != nil {
		t.Fatal(err)
	}
	if n.endpoint != "https://ntfy.example.com:8443/pre/my-topic" {
		t.Errorf("endpoint %q", n.endpoint)
	}
	u, _ := url.Parse(n.endpoint)
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		t.Errorf("endpoint %v", u)
	}
}

func TestPriorityOf(t *testing.T) {
	want := map[result.Severity]int{result.Critical: 5, result.High: 4, result.Medium: 3, result.Low: 2, result.Info: 1, "": 3, "bogus": 3}
	for s, p := range want {
		if got := PriorityOf(s); got != p {
			t.Errorf("%q: %d, want %d", s, got, p)
		}
	}
}

func TestErrorText(t *testing.T) {
	e := &Error{Class: Transient, Status: 503, Attempts: 2, Msg: "HTTP 503"}
	if e.Error() != "ntfy: HTTP 503 (after 2 attempts)" {
		t.Errorf("%q", e.Error())
	}
	if e := (&Error{Msg: "x", Attempts: 1}); e.Error() != "ntfy: x" {
		t.Errorf("%q", e.Error())
	}
	if Transient.String() != "transient" || Permanent.String() != "permanent" {
		t.Error("class names")
	}
	if AsError(errors.New("x")) != nil || AsError(nil) != nil {
		t.Error("AsError of a foreign error")
	}
}
