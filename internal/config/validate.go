package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
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
	uid     int
	ownerOf func(path string) (int, error)
}

func validate(root *yaml.Node, origins map[*yaml.Node]string, main string, opt options) (*Config, Errors) {
	v := &validator{origins: origins, main: main, uid: os.Getuid(), ownerOf: opt.ownerOf}
	cfg := &Config{StateDir: DefaultStateDir}
	if !isMapping(root) {
		v.fail(root, "the configuration root must be a mapping")
		return nil, v.errs
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, val := root.Content[i], root.Content[i+1]
		switch k.Value {
		case "host":
			cfg.Host = v.host(val)
		case "state_dir":
			if s, ok := v.str(val, "state_dir"); ok {
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
		default:
			v.fail(k, "unknown key "+strconv.Quote(k.Value))
		}
	}
	if cfg.Notify.Ntfy != nil && cfg.Notify.Ntfy.TokenFile != "" {
		v.checkTokenFile(v.token, cfg.Notify.Ntfy.TokenFile)
	}
	sort.SliceStable(v.errs, func(i, j int) bool {
		if v.errs[i].File != v.errs[j].File {
			return v.errs[i].File < v.errs[j].File
		}
		return v.errs[i].Line < v.errs[j].Line
	})
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

func (v *validator) str(n *yaml.Node, path string) (string, bool) {
	if !isScalar(n) {
		v.fail(n, path+": expected a string")
		return "", false
	}
	return n.Value, true
}

func (v *validator) boolVal(n *yaml.Node, path string) (bool, bool) {
	if !isScalar(n) {
		v.fail(n, path+": expected true or false")
		return false, false
	}
	b, err := strconv.ParseBool(n.Value)
	if err != nil {
		v.fail(n, path+": expected true or false, got "+strconv.Quote(n.Value))
		return false, false
	}
	return b, true
}

func (v *validator) host(n *yaml.Node) Host {
	var h Host
	if !isMapping(n) {
		v.fail(n, "host: expected a mapping")
		return h
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "profile":
			if s, ok := v.str(val, "host.profile"); ok {
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
				if b, ok := v.boolVal(iv, path+".enabled"); ok {
					c.Enabled = b
				}
			case "severity":
				if s, ok := v.str(iv, path+".severity"); ok {
					if !contains(severities, s) {
						v.fail(iv, path+".severity: "+strconv.Quote(s)+" is not one of "+strings.Join(severities, ", "))
					} else {
						c.Severity = s
					}
				}
			case "params":
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
	if !isMapping(n) {
		v.fail(n, "listeners: expected a mapping")
		return ls
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "allow":
			ls.Allow = v.allow(val, "listeners.allow")
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
				sawPort = true
				if s, ok := v.str(val, p+".port"); ok {
					port, err := strconv.Atoi(s)
					if err != nil {
						v.fail(val, p+".port: expected an integer, got "+strconv.Quote(s))
					} else if port < 1 || port > 65535 {
						v.fail(val, p+".port: must be between 1 and 65535, got "+strconv.Itoa(port))
					} else {
						l.Port = port
					}
				}
			case "proto":
				sawProto = true
				if s, ok := v.str(val, p+".proto"); ok {
					if s != "tcp" && s != "udp" {
						v.fail(val, p+".proto: "+strconv.Quote(s)+" is not tcp or udp")
					} else {
						l.Proto = s
					}
				}
			case "bind":
				if s, ok := v.str(val, p+".bind"); ok {
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
		if !isMapping(val) {
			v.fail(val, "authorized_keys.expected: expected a mapping of user name to fingerprint list")
			continue
		}
		for j := 0; j+1 < len(val.Content); j += 2 {
			uk, uv := val.Content[j], val.Content[j+1]
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
				if !isScalar(fp) {
					v.fail(fp, path+": expected a string fingerprint")
					continue
				}
				if !fingerprint.MatchString(fp.Value) {
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
				sawCheck = true
				if s, ok := v.str(val, p+".check"); ok {
					if s == "" {
						v.fail(val, p+".check: must not be empty")
					} else {
						e.Check = s
					}
				}
			case "match":
				if s, ok := v.str(val, p+".match"); ok {
					e.Match = s
				}
			case "reason":
				sawReason = true
				if s, ok := v.str(val, p+".reason"); ok {
					if strings.TrimSpace(s) == "" {
						v.fail(val, p+".reason: must not be empty")
					} else {
						e.Reason = s
					}
				}
			case "expires":
				sawExpires = true
				if s, ok := v.str(val, p+".expires"); ok {
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

func (v *validator) notify(n *yaml.Node) Notify {
	var nt Notify
	if !isMapping(n) {
		v.fail(n, "notify: expected a mapping")
		return nt
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "ntfy":
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
	sawTopic := false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "url":
			if s, ok := v.str(val, "notify.ntfy.url"); ok {
				v.ntfyURL(val, s)
				nf.URL = s
			}
		case "topic":
			sawTopic = true
			if s, ok := v.str(val, "notify.ntfy.topic"); ok {
				if s == "" {
					v.fail(val, "notify.ntfy.topic: must not be empty")
				} else {
					nf.Topic = s
				}
			}
		case "token_file":
			if s, ok := v.str(val, "notify.ntfy.token_file"); ok {
				if !filepath.IsAbs(s) {
					v.fail(val, "notify.ntfy.token_file: must be an absolute path")
				} else {
					nf.TokenFile = s
					v.token = val
				}
			}
		default:
			v.fail(k, "notify.ntfy: unknown key "+strconv.Quote(k.Value))
		}
	}
	if !sawTopic {
		v.fail(n, "notify.ntfy.topic: required when notify.ntfy is set")
	}
	return nf, true
}

func (v *validator) ntfyURL(n *yaml.Node, raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		v.fail(n, "notify.ntfy.url: "+strconv.Quote(raw)+" is not a valid absolute URL")
		return
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			v.fail(n, "notify.ntfy.url: http is only allowed for loopback hosts, got "+strconv.Quote(u.Hostname()))
		}
	default:
		v.fail(n, "notify.ntfy.url: scheme "+strconv.Quote(u.Scheme)+" is not http or https")
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (v *validator) checkTokenFile(n *yaml.Node, path string) {
	fi, err := os.Lstat(path)
	if err != nil {
		if isNotExist(err) {
			v.fail(n, "notify.ntfy.token_file: "+path+": does not exist")
		} else {
			v.fail(n, "notify.ntfy.token_file: "+path+": cannot stat: "+cleanErr(err))
		}
		return
	}
	if !fi.Mode().IsRegular() {
		found := "found " + fi.Mode().Type().String()
		if fi.Mode()&os.ModeSymlink != 0 {
			found = "it is a symlink"
		}
		v.fail(n, "notify.ntfy.token_file: "+path+": must be a regular file, "+found)
		return
	}
	if fi.Mode().Perm()&0o077 != 0 {
		v.fail(n, fmt.Sprintf("notify.ntfy.token_file: %s: permissions 0%03o grant access to group or other, want 0600 or stricter", path, fi.Mode().Perm()))
		return
	}
	uid, err := v.ownerOf(path)
	if err != nil {
		v.fail(n, "notify.ntfy.token_file: "+path+": cannot check owner: "+cleanErr(err))
		return
	}
	if uid != v.uid {
		v.fail(n, fmt.Sprintf("notify.ntfy.token_file: %s: owned by uid %d, expected uid %d", path, uid, v.uid))
	}
}

func contains(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}
