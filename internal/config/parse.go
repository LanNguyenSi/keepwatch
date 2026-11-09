package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

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
// empty file yields a nil root and no error.
func parseFile(file string) (*yaml.Node, map[*yaml.Node]string, *Error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, &Error{File: file, Msg: "cannot read: " + cleanErr(err)}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, nil, syntaxError(file, err)
		}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, nil, &Error{File: file, Msg: "unexpected content after the first document"}
	} else if !errors.Is(err, io.EOF) {
		return nil, nil, syntaxError(file, err)
	}

	origins := map[*yaml.Node]string{}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil, origins, nil
	}
	root := doc.Content[0]
	register(root, file, origins)
	return root, origins, nil
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

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }

func osReadDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}
