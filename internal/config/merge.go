package config

import (
	"fmt"
	"strconv"

	"go.yaml.in/yaml/v3"
)

func emptyMapping() *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
}

func isMapping(n *yaml.Node) bool { return n != nil && n.Kind == yaml.MappingNode }

func isSequence(n *yaml.Node) bool { return n != nil && n.Kind == yaml.SequenceNode }

func isScalar(n *yaml.Node) bool { return n != nil && n.Kind == yaml.ScalarNode }

// isNull reports a null document or null value (a bare ~, null or empty
// plain scalar after tag resolution).
func isNull(n *yaml.Node) bool { return isScalar(n) && n.ShortTag() == "!!null" }

// kindOf is the YAML kind of n with aliases resolved: mapping, sequence
// or scalar.
func kindOf(n *yaml.Node) yaml.Kind {
	for n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if n == nil {
		return 0
	}
	return n.Kind
}

// where is "file:line" of key, with the file taken from origins.
func where(key *yaml.Node, origins map[*yaml.Node]string) string {
	return origins[key] + ":" + strconv.Itoa(key.Line)
}

// mergeMapping merges src into dst per the package merge rule: mappings
// merge per key recursively with the later (src) value winning,
// sequences append (dst first, then src), scalars are replaced by src.
// A value that src replaces with one of a different kind (a mapping, a
// sequence or a scalar) is an error naming both places: validation runs
// on the merged tree, where the replaced value would never be looked at.
// A null src value contributes nothing when dst already has the key, at
// any depth: a drop-in file with a bare "notify:" (or a block whose
// lines are all commented out) must not blank the section a
// lower-numbered file set. The opposite direction still works: a null dst
// value is replaced by whatever src sets, whatever its kind. A null src
// value for a key dst does not have yet is kept, so that the validator
// treats it like the same null in a single file. prefix is the dotted
// path of the mappings above dst, for the message; origins names the
// file of every node.
func mergeMapping(dst, src *yaml.Node, prefix string, origins map[*yaml.Node]string, errs *Errors) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, val := src.Content[i], src.Content[i+1]
		if j := findKey(dst, key.Value); j >= 0 {
			dv := dst.Content[j+1]
			dk, vk := kindOf(dv), kindOf(val)
			switch {
			case isNull(val):
				// nothing to contribute
				continue
			case isNull(dv):
				// an earlier null does not block this value
			case dk != vk:
				*errs = append(*errs, Error{File: origins[key], Line: key.Line,
					Msg: fmt.Sprintf("%s in %s changes the type set in %s",
						prefix+key.Value, where(key, origins), where(dst.Content[j], origins))})
			}
			switch {
			case isMapping(dv) && isMapping(val):
				mergeMapping(dv, val, prefix+key.Value+".", origins, errs)
			case isSequence(dv) && isSequence(val):
				dv.Content = append(dv.Content, val.Content...)
			default:
				// The key goes with the value, so a later message names the
				// place that set it.
				dst.Content[j], dst.Content[j+1] = key, val
			}
			continue
		}
		dst.Content = append(dst.Content, key, val)
	}
}

func findKey(mapping *yaml.Node, key string) int {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return i
		}
	}
	return -1
}
