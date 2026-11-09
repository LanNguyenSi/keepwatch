package probes

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// paramReader reads typed parameters from a decoded YAML map and collects
// every problem, so a bad configuration is reported in one go. Values come
// from YAML decoding (string, bool, int, []any) or from Go callers
// ([]string).
type paramReader struct {
	m    map[string]any
	seen map[string]bool
	errs []string
}

func newParams(m map[string]any) *paramReader {
	return &paramReader{m: m, seen: map[string]bool{}}
}

func (p *paramReader) fail(format string, a ...any) {
	p.errs = append(p.errs, fmt.Sprintf(format, a...))
}

func (p *paramReader) raw(key string) (any, bool) {
	p.seen[key] = true
	v, ok := p.m[key]
	return v, ok
}

// str reads a string parameter and checks it with valid. A missing
// required parameter is an error; a missing optional one yields def
// without being validated.
func (p *paramReader) str(key string, required bool, def string, valid func(string) error) string {
	v, ok := p.raw(key)
	if !ok {
		if required {
			p.fail("%s: required", key)
		}
		return def
	}
	s, ok := v.(string)
	if !ok {
		p.fail("%s: expected a string, got %T", key, v)
		return def
	}
	if err := valid(s); err != nil {
		p.fail("%s: %v", key, err)
		return def
	}
	return s
}

// boolean reads a boolean parameter.
func (p *paramReader) boolean(key string, def bool) bool {
	v, ok := p.raw(key)
	if !ok {
		return def
	}
	b, ok := v.(bool)
	if !ok {
		p.fail("%s: expected true or false, got %T", key, v)
		return def
	}
	return b
}

// strList reads a list of strings, each checked with valid. A missing
// optional list yields def; an empty list is an error when nonEmpty.
func (p *paramReader) strList(key string, required, nonEmpty bool, def []string, valid func(string) error) []string {
	v, ok := p.raw(key)
	if !ok {
		if required {
			p.fail("%s: required", key)
		}
		return def
	}
	var items []string
	switch l := v.(type) {
	case []string:
		items = l
	case []any:
		for i, e := range l {
			s, ok := e.(string)
			if !ok {
				p.fail("%s[%d]: expected a string, got %T", key, i, e)
				return def
			}
			items = append(items, s)
		}
	default:
		p.fail("%s: expected a list of strings, got %T", key, v)
		return def
	}
	if nonEmpty && len(items) == 0 {
		p.fail("%s: must not be empty", key)
		return def
	}
	for i, s := range items {
		if err := valid(s); err != nil {
			p.fail("%s[%d]: %v", key, i, err)
			return def
		}
	}
	return items
}

// err returns the collected problems plus one for every unknown key, or nil.
func (p *paramReader) err() error {
	var unknown []string
	for k := range p.m {
		if !p.seen[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		p.fail("unknown parameter %q", k)
	}
	if len(p.errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(p.errs, "; "))
}

// argPattern returns a validator for a value that reaches a command line:
// it must match re, and a leading "-" is rejected explicitly (option
// injection) before the pattern is even consulted.
func argPattern(what string, re *regexp.Regexp) func(string) error {
	return func(s string) error {
		if strings.HasPrefix(s, "-") {
			return fmt.Errorf("%s %q must not start with %q", what, s, "-")
		}
		if !re.MatchString(s) {
			return fmt.Errorf("%s %q does not match %s", what, s, re)
		}
		return nil
	}
}
