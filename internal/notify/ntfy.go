package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NtfyConfig is what the ntfy implementation needs.
type NtfyConfig struct {
	// URL is the base address of the server (https, or http for a loopback
	// host), without credentials, query or fragment. A path prefix is kept:
	// a server behind a reverse proxy at /ntfy is reached at
	// https://host/ntfy.
	URL string
	// Topic is posted to as <URL>/<Topic>; [A-Za-z0-9_-], 1 to 64 characters.
	Topic string
	// ReadToken returns the bearer token, called for every Send, so a token
	// that changes on disk is picked up and a token file that went bad since
	// the configuration was loaded fails the send, not the start. Nil sends
	// no Authorization header.
	ReadToken func() ([]byte, error)
	// UserAgent is sent as User-Agent; empty means "keepwatch".
	UserAgent string
}

// Defaults of the ntfy client.
const (
	// DefaultTimeout bounds one request, from dialling to the last byte of
	// the answer.
	DefaultTimeout = 15 * time.Second
	// DefaultBackoff is the wait before the one retry.
	DefaultBackoff = 2 * time.Second
	// MaxRetryAfter is the longest Retry-After keepwatch waits for. A server
	// that asks for more gets no second request in this run.
	MaxRetryAfter = 30 * time.Second
	// maxAnswer bounds what is read of an answer.
	maxAnswer = 64 << 10
)

var (
	topicRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	tagRe   = regexp.MustCompile(`^[A-Za-z0-9_+-]{1,32}$`)
)

// Ntfy publishes to an ntfy server (https://docs.ntfy.sh/publish/).
type Ntfy struct {
	endpoint  string
	readToken func() ([]byte, error)
	userAgent string
	client    *http.Client
	timeout   time.Duration
	backoff   time.Duration
	sleep     func(context.Context, time.Duration) error
	roots     *x509.CertPool
	transport http.RoundTripper
}

// Option customises an Ntfy; production code uses none (tests do).
type Option func(*Ntfy)

// WithTimeout sets the timeout of one request.
func WithTimeout(d time.Duration) Option { return func(n *Ntfy) { n.timeout = d } }

// WithBackoff sets the wait before the one retry.
func WithBackoff(d time.Duration) Option { return func(n *Ntfy) { n.backoff = d } }

// WithSleep replaces the wait between the attempts.
func WithSleep(f func(context.Context, time.Duration) error) Option {
	return func(n *Ntfy) { n.sleep = f }
}

// WithRootCAs replaces the trusted certificate authorities (the system ones
// by default). Certificates are verified either way.
func WithRootCAs(p *x509.CertPool) Option { return func(n *Ntfy) { n.roots = p } }

// WithTransport replaces the HTTP transport. The client around it keeps its
// rules: no redirect is followed and every request has the timeout.
func WithTransport(rt http.RoundTripper) Option { return func(n *Ntfy) { n.transport = rt } }

// NewNtfy checks cfg and returns the notifier. It makes no request.
func NewNtfy(cfg NtfyConfig, opts ...Option) (*Ntfy, error) {
	u, err := url.Parse(cfg.URL)
	switch {
	case err != nil || u.Hostname() == "" || strings.HasSuffix(u.Host, ":"):
		return nil, errors.New("notify.ntfy.url is not a valid absolute URL")
	case u.User != nil:
		return nil, errors.New("notify.ntfy.url must not hold credentials: the token goes in token_file")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(cfg.URL, "#"):
		return nil, errors.New("notify.ntfy.url must not hold a query or a fragment")
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	case u.Scheme == "http":
		return nil, errors.New("notify.ntfy.url: http is only allowed for loopback hosts")
	default:
		return nil, errors.New("notify.ntfy.url: the scheme must be https")
	}
	if !topicRe.MatchString(cfg.Topic) {
		return nil, errors.New("notify.ntfy.topic must be 1 to 64 characters of A-Z a-z 0-9 _ -")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + cfg.Topic
	u.RawPath = ""
	n := &Ntfy{
		endpoint:  u.String(),
		readToken: cfg.ReadToken,
		userAgent: cfg.UserAgent,
		timeout:   DefaultTimeout,
		backoff:   DefaultBackoff,
		sleep:     sleepCtx,
	}
	if n.userAgent == "" {
		n.userAgent = "keepwatch"
	}
	for _, o := range opts {
		o(n)
	}
	n.client = n.newClient()
	return n, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newClient builds the HTTP client. It never uses a proxy from the
// environment (HTTP_PROXY and friends: the token would travel through
// whatever they name), verifies certificates, does not follow redirects
// (a redirect could take the bearer token to another host) and keeps no
// connection between runs.
func (n *Ntfy) newClient() *http.Client {
	rt := n.transport
	if rt == nil {
		d := &net.Dialer{Timeout: n.timeout}
		rt = &http.Transport{
			Proxy:                  nil,
			DialContext:            d.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: n.roots},
			TLSHandshakeTimeout:    n.timeout,
			ResponseHeaderTimeout:  n.timeout,
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
		}
	}
	return &http.Client{
		Transport:     rt,
		Timeout:       n.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Send publishes m: one request, and one more after a wait when the first
// failed on the network or with 5xx or 429. A 4xx other than 429, a redirect
// and any other answer end it at once. A Retry-After of up to MaxRetryAfter
// seconds is waited for (never less than the backoff); a longer one means no
// second request.
func (n *Ntfy) Send(ctx context.Context, m Message) error {
	req, err := n.build(m)
	if err != nil {
		return err
	}
	var last *Error
	for attempt := 1; attempt <= 2; attempt++ {
		wait, e := n.do(ctx, req, attempt)
		if e == nil {
			return nil
		}
		last = e
		if e.Class != Transient || attempt == 2 || ctx.Err() != nil {
			break
		}
		if wait > MaxRetryAfter {
			e.Msg += fmt.Sprintf("; the server asks to wait %s, longer than the %s keepwatch waits", wait.Round(time.Second), MaxRetryAfter)
			break
		}
		if wait < n.backoff {
			wait = n.backoff
		}
		if serr := n.sleep(ctx, wait); serr != nil {
			break
		}
	}
	return last
}

// request is a message ready to be sent.
type request struct {
	headers http.Header
	body    []byte
}

func (n *Ntfy) build(m Message) (*request, error) {
	if len(m.Body) > MaxBodyBytes {
		return nil, &Error{Class: Permanent, Msg: fmt.Sprintf("the message is %d bytes, the limit is %d", len(m.Body), MaxBodyBytes)}
	}
	if m.Priority < 0 || m.Priority > 5 {
		return nil, &Error{Class: Permanent, Msg: "invalid priority"}
	}
	h := http.Header{}
	if title := headerValue(m.Title, MaxTitleBytes); title != "" {
		h.Set("Title", title)
	}
	if m.Priority != 0 {
		h.Set("Priority", strconv.Itoa(m.Priority))
	}
	var tags []string
	for _, t := range m.Tags {
		if tagRe.MatchString(t) && len(tags) < maxTags {
			tags = append(tags, t)
		}
	}
	if len(tags) > 0 {
		h.Set("Tags", strings.Join(tags, ","))
	}
	if m.Markdown {
		h.Set("Markdown", "yes")
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("User-Agent", headerValue(n.userAgent, 100))
	if n.readToken != nil {
		tok, err := n.readToken()
		if err != nil {
			return nil, &Error{Class: Permanent, Msg: "the token cannot be read: " + headerValue(err.Error(), 300)}
		}
		if !validToken(tok) {
			return nil, &Error{Class: Permanent, Msg: "the token holds characters that are not allowed in a header (space, control or non-ASCII characters)"}
		}
		h.Set("Authorization", "Bearer "+string(tok))
	}
	return &request{headers: h, body: []byte(m.Body)}, nil
}

// do makes one request. wait is the Retry-After of the answer.
func (n *Ntfy) do(ctx context.Context, r *request, attempt int) (wait time.Duration, _ *Error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(r.body))
	if err != nil {
		return 0, &Error{Class: Permanent, Attempts: attempt, Msg: "cannot build the request"}
	}
	req.Header = r.headers.Clone()
	req.ContentLength = int64(len(r.body))
	resp, err := n.client.Do(req)
	if err != nil {
		return 0, &Error{Class: Transient, Attempts: attempt, Msg: "no answer: " + netErr(err)}
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return 0, nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return 0, &Error{Class: Permanent, Status: resp.StatusCode, Attempts: attempt,
			Msg: fmt.Sprintf("HTTP %d: the server answered with a redirect, which is not followed (the url in the configuration should be the final address)", resp.StatusCode)}
	}
	e := &Error{Status: resp.StatusCode, Attempts: attempt, Msg: fmt.Sprintf("HTTP %d%s", resp.StatusCode, serverReason(answer))}
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		e.Class = Transient
		wait = retryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	return wait, e
}

// serverReason extracts the "error" text of an ntfy answer ({"code":...,
// "http":...,"error":"..."}), cut and with every character outside printable
// ASCII replaced; empty when there is none. It is text from the server: the
// caller redacts it like any other.
func serverReason(b []byte) string {
	const key = `"error"`
	i := bytes.Index(b, []byte(key))
	if i < 0 {
		return ""
	}
	rest := bytes.TrimLeft(b[i+len(key):], " \t\r\n")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = bytes.TrimLeft(rest[1:], " \t\r\n")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	var sb strings.Builder
	for j := 0; j < len(rest) && rest[j] != '"' && sb.Len() < 200; j++ {
		c := rest[j]
		if c == '\\' && j+1 < len(rest) {
			j++
			c = '?'
		}
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		sb.WriteByte(c)
	}
	if sb.Len() == 0 {
		return ""
	}
	return ": " + sb.String()
}

// netErr describes a transport error without the URL (net/http puts it in).
func netErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return headerValue(err.Error(), 300)
}

// retryAfter parses a Retry-After value: seconds or an HTTP date. Zero when
// absent or unusable.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		if secs > 24*3600 {
			secs = 24 * 3600
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// headerValue makes s fit in an HTTP header value: printable ASCII only
// (everything else, CR and LF included, becomes '?'), trimmed, and at most
// max bytes.
func headerValue(s string, max int) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 0x20 && r <= 0x7e:
			b = append(b, byte(r))
		default:
			b = append(b, '?')
		}
		if len(b) >= max {
			break
		}
	}
	return strings.TrimSpace(string(b))
}

func validToken(t []byte) bool {
	if len(t) == 0 {
		return false
	}
	for _, c := range t {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}
