package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Error is a single configuration problem with its origin. Line is 0 for
// problems that have no line, for example a missing file.
type Error struct {
	File string
	Line int
	Msg  string
}

func (e Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	}
	return e.File + ": " + e.Msg
}

// Errors is a non-empty set of configuration problems. All problems
// found in one load are reported, not only the first.
type Errors []Error

func (es Errors) Error() string {
	s := ""
	for i, e := range es {
		if i > 0 {
			s += "\n"
		}
		s += e.Error()
	}
	return s
}

// parseFile decodes one YAML file into its root node. A known-fields
// decoder is used so that strictness is configured at the decode layer;
// the schema itself is validated against the node tree so that every
// error can name file and line. The second result maps every node of
// this file to the file name for the merged-tree error reporting. An
// empty file yields a nil root and no error. Problems found while
// parsing (syntax, content after the first document reported at the
// line of the second document, duplicate keys within one mapping at
// any depth) are returned as Errors. A file with a syntax problem
// yields a nil root; a file with duplicate keys still returns its
// root, which is merged and validated, and Load fails on the kept
// errors.
func parseFile(file string, p securePolicy) (*yaml.Node, map[*yaml.Node]string, Errors) {
	origins := map[*yaml.Node]string{}
	f, _, err := openSecure(file, p)
	if err != nil {
		return nil, origins, Errors{{File: file, Msg: "cannot read: " + fileErr(err, file)}}
	}
	data, err := readCapped(f, maxConfigSize)
	f.Close()
	if err != nil {
		return nil, origins, Errors{{File: file, Msg: "cannot read: " + fileErr(err, file)}}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, origins, Errors{*syntaxError(file, err)}
		}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, origins, Errors{{File: file, Line: nodeLine(&extra), Msg: "unexpected content after the first document"}}
	} else if !errors.Is(err, io.EOF) {
		return nil, origins, Errors{*syntaxError(file, err)}
	}

	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil, origins, nil
	}
	root := doc.Content[0]
	register(root, file, origins)
	var errs Errors
	walkDuplicate(root, file, &errs)
	return root, origins, errs
}

// nodeLine reports the best line for a decoded node: its own line, or
// the line of its first child for wrapper nodes such as documents.
func nodeLine(n *yaml.Node) int {
	if n.Line > 0 {
		return n.Line
	}
	if len(n.Content) > 0 {
		return n.Content[0].Line
	}
	return 0
}

// walkDuplicate reports every key that appears more than once in the
// same mapping, at any depth. Node decoding does not enforce yaml.v3's
// unique-key check, so duplicates would silently drop the earlier
// value. The error names the line of the repeated key and the line of
// the first occurrence.
func walkDuplicate(n *yaml.Node, file string, errs *Errors) {
	if n.Kind == yaml.MappingNode {
		seen := map[string]int{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			if key.Kind == yaml.ScalarNode {
				if first, dup := seen[key.Value]; dup {
					*errs = append(*errs, Error{File: file, Line: key.Line,
						Msg: fmt.Sprintf("duplicate key %q (first at line %d)", key.Value, first)})
				} else {
					seen[key.Value] = key.Line
				}
			}
			walkDuplicate(key, file, errs)
			walkDuplicate(val, file, errs)
		}
		return
	}
	for _, c := range n.Content {
		walkDuplicate(c, file, errs)
	}
}

func register(n *yaml.Node, file string, origins map[*yaml.Node]string) {
	origins[n] = file
	for _, c := range n.Content {
		register(c, file, origins)
	}
}

var syntaxLine = regexp.MustCompile(`^yaml: (?:line (\d+): )?`)

func syntaxError(file string, err error) *Error {
	msg := cleanErr(err)
	line := 0
	if m := syntaxLine.FindStringSubmatch(msg); m != nil {
		if m[1] != "" {
			line, _ = strconv.Atoi(m[1])
		}
		msg = msg[len(m[0]):]
	}
	return &Error{File: file, Line: line, Msg: msg}
}

func cleanErr(err error) string { return err.Error() }

// fileErr is the message of err for an Error whose File already names
// the path. A *fs.PathError renders as "<op> <path>: <reason>", which
// would name the path twice, so it is reduced to "<op>: <reason>"; any
// other message that starts with the path loses that prefix.
func fileErr(err error, path string) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return trimPath(cleanErr(err), path)
}

// trimPath drops a leading "<path>: " from msg: an Error is already
// prefixed with its File, so a message that starts with the same path
// must not name it twice.
func trimPath(msg, path string) string {
	if p := path + ": "; strings.HasPrefix(msg, p) {
		return msg[len(p):]
	}
	return msg
}

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
