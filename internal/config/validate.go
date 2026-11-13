package config

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
)

var (
	severities  = []string{"info", "low", "medium", "high", "critical"}
	fingerprint = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}={0,1}$`)
)

type validator struct {
	origins map[*yaml.Node]string
	main    string
	errs    Errors
	token   *yaml.Node // the notify.ntfy.token_file node, for the secret checks
	ownerOf OwnerOf
}

func validate(root *yaml.Node, origins map[*yaml.Node]string, main string, opt options) (*Config, Errors) {
	v := &validator{origins: origins, main: main, ownerOf: opt.ownerOf}
	cfg := &Config{StateDir: DefaultStateDir, Watch: defaultWatch(), ownerOf: opt.ownerOf}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, val := root.Content[i], root.Content[i+1]
		switch k.Value {
		case "host":
			cfg.Host = v.host(val)
		case "state_dir":
			if s, present, ok := v.str(val, "state_dir"); ok && present {
				if !filepath.IsAbs(s) {
					v.fail(val, "state_dir: must be an absolute path")
				} else {
					cfg.StateDir = s
				}
			}
		case "checks":
			cfg.Checks = v.checks(val)
		case "listeners":
			cfg.Listeners = v.listeners(val)
		case "authorized_keys":
			cfg.AuthorizedKeys = v.authorizedKeys(val)
		case "exceptions":
			cfg.Exceptions = v.exceptions(val)
		case "notify":
			cfg.Notify = v.notify(val)
		case "redact":
			cfg.Redact = v.redact(val)
		case "watch":
			cfg.Watch = v.watch(val)
		default:
			v.fail(k, "unknown key "+strconv.Quote(k.Value))
		}
	}
	if cfg.Notify.Ntfy != nil && cfg.Notify.Ntfy.TokenFile != "" {
		v.checkTokenFile(v.token, cfg.Notify.Ntfy.TokenFile)
	}
	if len(v.errs) == 0 {
		return cfg, nil
	}
	return nil, v.errs
}

func (v *validator) fail(n *yaml.Node, msg string) {
	file := v.origins[n]
	if file == "" {
		file = v.main
	}
	v.errs = append(v.errs, Error{File: file, Line: n.Line, Msg: msg})
}

// str validates a string-valued scalar by its resolved tag, so quoted
// "22" or 1 are not strings. A !!null value counts as absent: the
// second result is false without an error, and the caller decides
// whether absent is fine (optional) or an error (required, via its
// own presence check). The third result is false when an error was
// reported.
func (v *validator) str(n *yaml.Node, path string) (string, bool, bool) {
	if !isScalar(n) {
		v.fail(n, path+": expected a string")
		return "", false, false
	}
	switch n.ShortTag() {
	case "!!null":
		return "", false, true
	case "!!str":
		return n.Value, true, true
	default:
		v.fail(n, path+": expected a string")
		return "", false, false
	}
}

// boolVal validates a boolean scalar (tag !!bool): 1 and "false" are
// not booleans. Null is absent; see str for the result pattern.
func (v *validator) boolVal(n *yaml.Node, path string) (bool, bool, bool) {
	if !isScalar(n) {
		v.fail(n, path+": expected true or false")
		return false, false, false
	}
	switch n.ShortTag() {
	case "!!null":
		return false, false, true
	case "!!bool":
		b, err := strconv.ParseBool(n.Value)
		if err != nil {
			v.fail(n, path+": expected true or false, got "+strconv.Quote(n.Value))
			return false, false, false
		}
		return b, true, true
	default:
		v.fail(n, path+": expected true or false, got "+strconv.Quote(n.Value))
		return false, false, false
	}
}

// intVal validates an integer scalar (tag !!int): a quoted "22" is a
// string, not an integer. Null is absent; see str.
func (v *validator) intVal(n *yaml.Node, path string) (int, bool, bool) {
	if !isScalar(n) {
		v.fail(n, path+": expected an integer")
		return 0, false, false
	}
	switch n.ShortTag() {
	case "!!null":
		return 0, false, true
	case "!!int":
		i, err := strconv.ParseInt(n.Value, 0, 64)
		if err != nil {
			v.fail(n, path+": expected an integer, got "+strconv.Quote(n.Value))
			return 0, false, false
		}
		return int(i), true, true
	default:
		v.fail(n, path+": expected an integer, got "+strconv.Quote(n.Value))
		return 0, false, false
	}
}

// date returns the text of an expires value: a quoted string or a
// plain date (yaml resolves plain YYYY-MM-DD to !!timestamp). Null is
// absent; see str. The caller parses the text.
func (v *validator) date(n *yaml.Node, path string) (string, bool, bool) {
	if !isScalar(n) {
		v.fail(n, path+": expected a date in YYYY-MM-DD form")
		return "", false, false
	}
	switch n.ShortTag() {
	case "!!null":
		return "", false, true
	case "!!str", "!!timestamp":
		return n.Value, true, true
	default:
		v.fail(n, path+": expected a date in YYYY-MM-DD form")
		return "", false, false
	}
}

func (v *validator) host(n *yaml.Node) Host {
	var h Host
	if isNull(n) { // a null section counts as absent
		return h
	}
	if !isMapping(n) {
		v.fail(n, "host: expected a mapping")
		return h
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "profile":
			if s, present, ok := v.str(val, "host.profile"); ok && present {
				h.Profile = s
			}
		default:
			v.fail(k, "host: unknown key "+strconv.Quote(k.Value))
		}
	}
	return h
}

func (v *validator) checks(n *yaml.Node) map[string]Check {
	out := map[string]Check{}
	if isNull(n) { // a null section counts as absent
		return out
	}
	if !isMapping(n) {
		v.fail(n, "checks: expected a mapping")
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		id := k.Value
		if id == "" {
			v.fail(k, "checks: a check id must not be empty")
			continue
		}
		path := "checks." + id
		if !isMapping(val) {
			v.fail(val, path+": expected a mapping")
			continue
		}
		c := Check{Enabled: true}
		for j := 0; j+1 < len(val.Content); j += 2 {
			ik, iv := val.Content[j], val.Content[j+1]
			switch ik.Value {
			case "enabled":
				if b, present, ok := v.boolVal(iv, path+".enabled"); ok && present {
					c.Enabled = b
				}
			case "severity":
				if s, present, ok := v.str(iv, path+".severity"); ok && present {
					if !contains(severities, s) {
						v.fail(iv, path+".severity: "+strconv.Quote(s)+" is not one of "+strings.Join(severities, ", "))
					} else {
						c.Severity = s
					}
				}
			case "params":
				if isNull(iv) { // a null params counts as absent
					continue
				}
				if !isMapping(iv) {
					v.fail(iv, path+".params: expected a mapping")
					continue
				}
				var m map[string]any
				if err := iv.Decode(&m); err != nil {
					v.fail(iv, path+".params: "+cleanErr(err))
					continue
				}
				c.Params = m
			default:
				v.fail(ik, path+": unknown key "+strconv.Quote(ik.Value))
			}
		}
		out[id] = c
	}
	return out
}

func (v *validator) listeners(n *yaml.Node) Listeners {
	var ls Listeners
	if isNull(n) { // a null section counts as absent
		return ls
	}
	if !isMapping(n) {
		v.fail(n, "listeners: expected a mapping")
		return ls
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "allow":
			if !isNull(val) { // a null list counts as absent
				ls.Allow = v.allow(val, "listeners.allow")
			}
		default:
			v.fail(k, "listeners: unknown key "+strconv.Quote(k.Value))
		}
	}
	return ls
}

func (v *validator) allow(seq *yaml.Node, path string) []Listener {
	var out []Listener
	if !isSequence(seq) {
		v.fail(seq, path+": expected a list")
		return out
	}
	for idx, entry := range seq.Content {
		p := fmt.Sprintf("%s[%d]", path, idx)
		if !isMapping(entry) {
			v.fail(entry, p+": expected a mapping")
			continue
		}
		l := Listener{Bind: "*"}
		sawPort, sawProto := false, false
		for j := 0; j+1 < len(entry.Content); j += 2 {
			k, val := entry.Content[j], entry.Content[j+1]
			switch k.Value {
			case "port":
				if port, present, ok := v.intVal(val, p+".port"); ok && present {
					sawPort = true
					if port < 1 || port > 65535 {
						v.fail(val, p+".port: must be between 1 and 65535, got "+strconv.Itoa(port))
					} else {
						l.Port = port
					}
				}
			case "proto":
				if s, present, ok := v.str(val, p+".proto"); ok && present {
					sawProto = true
					if s != "tcp" && s != "udp" {
						v.fail(val, p+".proto: "+strconv.Quote(s)+" is not tcp or udp")
					} else {
						l.Proto = s
					}
				}
			case "bind":
				if s, present, ok := v.str(val, p+".bind"); ok && present {
					if s != "*" && net.ParseIP(s) == nil {
						v.fail(val, p+".bind: "+strconv.Quote(s)+" is not an IP literal or \"*\"")
					} else {
						l.Bind = s
					}
				}
			default:
				v.fail(k, p+": unknown key "+strconv.Quote(k.Value))
			}
		}
		if !sawPort {
			v.fail(entry, p+": port is required")
		}
		if !sawProto {
			v.fail(entry, p+": proto is required")
		}
		out = append(out, l)
	}
	return out
}

func (v *validator) authorizedKeys(n *yaml.Node) AuthorizedKeys {
	ak := AuthorizedKeys{Expected: map[string][]string{}}
	if isNull(n) { // a null section counts as absent
		return ak
	}
	if !isMapping(n) {
		v.fail(n, "authorized_keys: expected a mapping")
		return ak
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		if k.Value != "expected" {
			v.fail(k, "authorized_keys: unknown key "+strconv.Quote(k.Value))
			continue
		}
		if isNull(val) { // a null expected counts as absent
			continue
		}
		if !isMapping(val) {
			v.fail(val, "authorized_keys.expected: expected a mapping of user name to fingerprint list")
			continue
		}
		for j := 0; j+1 < len(val.Content); j += 2 {
			uk, uv := val.Content[j], val.Content[j+1]
			if !isScalar(uk) || uk.ShortTag() != "!!str" {
				v.fail(uk, "authorized_keys.expected: expected a string user name")
				continue
			}
			user := uk.Value
			if user == "" {
				v.fail(uk, "authorized_keys.expected: a user name must not be empty")
				continue
			}
			path := "authorized_keys.expected." + user
			if !isSequence(uv) {
				v.fail(uv, path+": expected a list of fingerprints")
				continue
			}
			for _, fp := range uv.Content {
				if !isScalar(fp) || fp.ShortTag() != "!!str" || !fingerprint.MatchString(fp.Value) {
					v.fail(fp, path+": "+strconv.Quote(fp.Value)+" is not a SHA256:<base64> fingerprint")
					continue
				}
				ak.Expected[user] = append(ak.Expected[user], fp.Value)
			}
		}
	}
	return ak
}

func (v *validator) exceptions(seq *yaml.Node) []Exception {
	var out []Exception
	if isNull(seq) { // a null section counts as absent
		return out
	}
	if !isSequence(seq) {
		v.fail(seq, "exceptions: expected a list")
		return out
	}
	for idx, entry := range seq.Content {
		p := fmt.Sprintf("exceptions[%d]", idx)
		if !isMapping(entry) {
			v.fail(entry, p+": expected a mapping")
			continue
		}
		var e Exception
		sawCheck, sawReason, sawExpires := false, false, false
		for j := 0; j+1 < len(entry.Content); j += 2 {
			k, val := entry.Content[j], entry.Content[j+1]
			switch k.Value {
			case "check":
				if s, present, ok := v.str(val, p+".check"); ok && present {
					sawCheck = true
					if s == "" {
						v.fail(val, p+".check: must not be empty")
					} else {
						e.Check = s
					}
				}
			case "match":
				if s, present, ok := v.str(val, p+".match"); ok && present {
					e.Match = s
				}
			case "reason":
				if s, present, ok := v.str(val, p+".reason"); ok && present {
					sawReason = true
					if strings.TrimSpace(s) == "" {
						v.fail(val, p+".reason: must not be empty")
					} else {
						e.Reason = s
					}
				}
			case "expires":
				if s, present, ok := v.date(val, p+".expires"); ok && present {
					sawExpires = true
					t, err := parseDate(s)
					if err != nil {
						v.fail(val, p+".expires: "+strconv.Quote(s)+" is not a date in YYYY-MM-DD form")
					} else {
						e.Expires = t
					}
				}
			default:
				v.fail(k, p+": unknown key "+strconv.Quote(k.Value))
			}
		}
		if !sawCheck {
			v.fail(entry, p+": check is required")
		}
		if !sawReason {
			v.fail(entry, p+": reason is required")
		}
		if !sawExpires {
			v.fail(entry, p+": expires is required")
		}
		out = append(out, e)
	}
	return out
}

// redact validates the redact section: patterns is a list of regular
// expressions, each compiled here so that a bad one is a config error with
// file and line and never a surprise in the middle of a run. The limits are
// the redact package's: at most redact.MaxPatterns patterns, each at most
// redact.MaxPatternLen bytes, valid RE2 syntax, and none that matches the
// empty string. The limit on the count applies to the merged list.
func (v *validator) redact(n *yaml.Node) Redact {
	var r Redact
	if isNull(n) { // a null section counts as absent
		return r
	}
	if !isMapping(n) {
		v.fail(n, "redact: expected a mapping")
		return r
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		if k.Value != "patterns" {
			v.fail(k, "redact: unknown key "+strconv.Quote(k.Value))
			continue
		}
		if isNull(val) { // a null list counts as absent
			continue
		}
		if !isSequence(val) {
			v.fail(val, "redact.patterns: expected a list of regular expressions")
			continue
		}
		for j, p := range val.Content {
			path := fmt.Sprintf("redact.patterns[%d]", j)
			if !isScalar(p) || p.ShortTag() != "!!str" {
				v.fail(p, path+": expected a string")
				continue
			}
			if err := redact.ValidatePattern(p.Value); err != nil {
				v.fail(p, path+": "+err.Error())
				continue
			}
			r.Patterns = append(r.Patterns, p.Value)
		}
		if len(val.Content) > redact.MaxPatterns {
			v.fail(val, fmt.Sprintf("redact.patterns: %d patterns, the limit is %d", len(val.Content), redact.MaxPatterns))
		}
	}
	return r
}

func (v *validator) notify(n *yaml.Node) Notify {
	var nt Notify
	if isNull(n) { // a null section counts as absent
		return nt
	}
	if !isMapping(n) {
		v.fail(n, "notify: expected a mapping")
		return nt
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "ntfy":
			if isNull(val) { // a null ntfy counts as absent
				continue
			}
			nf, ok := v.ntfy(val)
			if ok {
				nt.Ntfy = nf
			}
		default:
			v.fail(k, "notify: unknown key "+strconv.Quote(k.Value))
		}
	}
	return nt
}

func (v *validator) ntfy(n *yaml.Node) (*Ntfy, bool) {
	if !isMapping(n) {
		v.fail(n, "notify.ntfy: expected a mapping")
		return nil, false
	}
	nf := &Ntfy{}
	sawTopic, sawURL := false, false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "url":
			if s, present, ok := v.str(val, "notify.ntfy.url"); ok && present {
				sawURL = true
				v.ntfyURL(val, s)
				nf.URL = s
			}
		case "topic":
			if s, present, ok := v.str(val, "notify.ntfy.topic"); ok && present {
				sawTopic = true
				if err := notify.ValidateTopic(s); err != nil {
					v.fail(val, err.Error())
				} else {
					nf.Topic = s
				}
			}
		case "token_file":
			if s, present, ok := v.str(val, "notify.ntfy.token_file"); ok && present {
				switch {
				case !filepath.IsAbs(s):
					v.fail(val, "notify.ntfy.token_file: must be an absolute path")
				case filepath.Clean(s) != s:
					// The directory check is lexical (filepath.Dir) while
					// the kernel resolves "link/.." through the symlink: an
					// unclean path could check one directory and open
					// another.
					v.fail(val, "notify.ntfy.token_file: must be a clean path (no '.', '..' or repeated '/')")
				default:
					nf.TokenFile = s
					v.token = val
				}
			}
		default:
			v.fail(k, "notify.ntfy: unknown key "+strconv.Quote(k.Value))
		}
	}
	if !sawURL {
		v.fail(n, "notify.ntfy.url: required when notify.ntfy is set")
	}
	if !sawTopic {
		v.fail(n, "notify.ntfy.topic: required when notify.ntfy is set")
	}
	return nf, true
}

// ntfyURL applies notify.ValidateURL, the rule NewNtfy applies too. Its
// message does not hold the URL, which may carry credentials.
func (v *validator) ntfyURL(n *yaml.Node, raw string) {
	if err := notify.ValidateURL(raw); err != nil {
		v.fail(n, err.Error())
	}
}

// Defaults of the watch section, the parameters the watch rules use
// when a key is absent. docs/configuration.md lists every key with its
// default and range.
const (
	watchDefaultLearningPeriod       = 7 * 24 * time.Hour
	watchDefaultBruteforceThreshold  = 5
	watchDefaultBruteforceWindow     = 10 * time.Minute
	watchDefaultRestartLoopThreshold = 3
	watchDefaultRestartLoopWindow    = 15 * time.Minute
	watchDefaultNotifyQueue          = 100
	watchDefaultNotifyPerIncident    = time.Hour
	watchDefaultNotifyGlobalPerMin   = 6
)

// Ranges of the watch section: every duration is at least the minimum
// of its key (watchMinWindow for the rule windows,
// watchMinLearningPeriod for learning_period, watchMinPerIncident for
// per_incident_interval) and at most watchMaxDuration; queue is 1 to
// watchMaxQueue, global_per_minute 1 to watchMaxPerMinute and
// thresholds 1 to watchMaxThreshold.
const (
	watchMaxDuration       = 720 * time.Hour // 30 days
	watchMaxQueue          = 1000
	watchMaxPerMinute      = 60
	watchMaxThreshold      = 10000
	watchMinWindow         = time.Second
	watchMinLearningPeriod = time.Hour
	watchMinPerIncident    = time.Minute
)

// defaultWatch is the watch section of a configuration that does not
// mention it, or that nulls the section or one of its nested mappings.
func defaultWatch() Watch {
	return Watch{
		LearningPeriod: watchDefaultLearningPeriod,
		SSHBruteforce:  WatchRule{Threshold: watchDefaultBruteforceThreshold, Window: watchDefaultBruteforceWindow},
		RestartLoop:    WatchRule{Threshold: watchDefaultRestartLoopThreshold, Window: watchDefaultRestartLoopWindow},
		Notify: WatchNotify{
			Queue:               watchDefaultNotifyQueue,
			PerIncidentInterval: watchDefaultNotifyPerIncident,
			GlobalPerMinute:     watchDefaultNotifyGlobalPerMin,
		},
	}
}

func (v *validator) watch(n *yaml.Node) Watch {
	w := defaultWatch()
	if isNull(n) { // a null section counts as absent
		return w
	}
	if !isMapping(n) {
		v.fail(n, "watch: expected a mapping")
		return w
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "enabled":
			if b, present, ok := v.boolVal(val, "watch.enabled"); ok && present {
				w.Enabled = b
			}
		case "learning_period":
			v.watchDuration(val, "watch.learning_period", watchMinLearningPeriod, &w.LearningPeriod)
		case "ssh_bruteforce":
			if isNull(val) { // a null rule counts as absent: its defaults stay
				continue
			}
			v.watchRule(val, "watch.ssh_bruteforce", &w.SSHBruteforce)
		case "restart_loop":
			if isNull(val) { // a null rule counts as absent: its defaults stay
				continue
			}
			v.watchRule(val, "watch.restart_loop", &w.RestartLoop)
		case "notify":
			if isNull(val) { // a null section counts as absent: its defaults stay
				continue
			}
			v.watchNotify(val, &w.Notify)
		default:
			v.fail(k, "watch: unknown key "+strconv.Quote(k.Value))
		}
	}
	return w
}

// watchRule validates one threshold/window rule mapping; *r holds the
// rule's defaults, which stay for keys that are absent or null.
func (v *validator) watchRule(n *yaml.Node, name string, r *WatchRule) {
	if !isMapping(n) {
		v.fail(n, name+": expected a mapping")
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "threshold":
			if t, present, ok := v.intVal(val, name+".threshold"); ok && present {
				if t < 1 || t > watchMaxThreshold {
					v.fail(val, name+".threshold: must be between 1 and "+strconv.Itoa(watchMaxThreshold)+", got "+strconv.Itoa(t))
				} else {
					r.Threshold = t
				}
			}
		case "window":
			v.watchDuration(val, name+".window", watchMinWindow, &r.Window)
		default:
			v.fail(k, name+": unknown key "+strconv.Quote(k.Value))
		}
	}
}

// watchNotify validates the watch notify mapping; *q holds its defaults.
func (v *validator) watchNotify(n *yaml.Node, q *WatchNotify) {
	if !isMapping(n) {
		v.fail(n, "watch.notify: expected a mapping")
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "queue":
			if x, present, ok := v.intVal(val, "watch.notify.queue"); ok && present {
				if x < 1 || x > watchMaxQueue {
					v.fail(val, "watch.notify.queue: must be between 1 and "+strconv.Itoa(watchMaxQueue)+", got "+strconv.Itoa(x))
				} else {
					q.Queue = x
				}
			}
		case "per_incident_interval":
			v.watchDuration(val, "watch.notify.per_incident_interval", watchMinPerIncident, &q.PerIncidentInterval)
		case "global_per_minute":
			if x, present, ok := v.intVal(val, "watch.notify.global_per_minute"); ok && present {
				if x < 1 || x > watchMaxPerMinute {
					v.fail(val, "watch.notify.global_per_minute: must be between 1 and "+strconv.Itoa(watchMaxPerMinute)+", got "+strconv.Itoa(x))
				} else {
					q.GlobalPerMinute = x
				}
			}
		default:
			v.fail(k, "watch.notify: unknown key "+strconv.Quote(k.Value))
		}
	}
}

// watchDurationFormat is the format sentence of the duration errors:
// the grammar of parseWatchDuration, in one sentence.
const watchDurationFormat = "want one number (no leading zeros, at most 5 digits) and one unit (s, m, h or d), for example 90m, 2h or 7d"

// watchDuration validates one duration and stores it when it is in
// range (at least min and at most watchMaxDuration). A null counts as
// absent and leaves the current value.
func (v *validator) watchDuration(n *yaml.Node, path string, min time.Duration, dst *time.Duration) {
	if !isScalar(n) {
		v.fail(n, path+": expected a duration: "+watchDurationFormat)
		return
	}
	switch n.ShortTag() {
	case "!!null":
		return // absent: the current value stays
	case "!!str":
	default:
		v.fail(n, path+": expected a duration: "+watchDurationFormat)
		return
	}
	d, err := parseWatchDuration(n.Value)
	if err != nil {
		v.fail(n, path+": "+strconv.Quote(n.Value)+" is not a duration: "+watchDurationFormat)
		return
	}
	if d < min || d > watchMaxDuration {
		v.fail(n, path+": must be between "+min.String()+" and "+watchMaxDuration.String()+", got "+d.String())
		return
	}
	*dst = d
}

// parseWatchDuration parses a watch duration with the grammar of
// install.ParseInterval (that package is not imported here, to keep the
// dependency one-way): one positive number without leading zeros, at
// most five digits, and exactly one unit (s, m, h or d), lower case,
// nothing else: no spaces, no sign, no fraction, no second unit. At
// most five digits, so no conversion overflows; the range check is the
// caller's.
func parseWatchDuration(s string) (time.Duration, error) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	num, unit := s[:i], s[i:]
	if num == "" || len(num) > 5 || num[0] == '0' {
		return 0, fmt.Errorf("%q is not a duration", s)
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration", s)
	}
	var scale time.Duration
	switch unit {
	case "s":
		scale = time.Second
	case "m":
		scale = time.Minute
	case "h":
		scale = time.Hour
	case "d":
		scale = 24 * time.Hour
	default:
		return 0, fmt.Errorf("%q is not a duration", s)
	}
	return time.Duration(n) * scale, nil
}

// checkTokenFile validates the token file's existence, type, size,
// link count, permissions and ownership through the same secure-open
// used by ReadToken, then closes it without reading it. Every check
// runs on the open fd, and the file's directory and each directory above
// it pass the conf.d directory rules, so a later open sees any path
// swap; ReadToken re-checks when it opens.
func (v *validator) checkTokenFile(n *yaml.Node, path string) {
	// The directory holding the secret and every directory above it are
	// checked like conf.d, and the token is opened through the checked
	// directory: a group-writable or foreign directory at any depth lets
	// another user swap the token between validation and the read.
	root, derr := openCheckedDir(filepath.Dir(path), v.ownerOf, false)
	if derr != nil {
		if isNotExist(derr) {
			v.fail(n, "notify.ntfy.token_file: "+path+": does not exist")
		} else {
			v.fail(n, "notify.ntfy.token_file: "+cleanErr(derr))
		}
		return
	}
	defer root.Close()
	f, _, err := openSecureIn(root, filepath.Base(path), path, tokenPolicy(v.ownerOf))
	if err != nil {
		if isNotExist(err) {
			v.fail(n, "notify.ntfy.token_file: "+path+": does not exist")
		} else {
			v.fail(n, "notify.ntfy.token_file: "+err.Error())
		}
		return
	}
	f.Close()
}

func contains(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}
