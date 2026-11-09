package config

import (
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

// mergeMapping merges src into dst per the package merge rule: mappings
// merge per key recursively with the later (src) value winning,
// sequences append (dst first, then src), scalars and kind changes are
// replaced by src. A null src value contributes nothing when dst
// already has the key, at any depth: a drop-in file with a bare
// "notify:" (or a block whose lines are all commented out) must not
// blank the section a lower-numbered file set. The opposite direction
// still works: a null dst value is replaced by whatever src sets. A
// null src value for a key dst does not have yet is kept, so that the
// validator treats it like the same null in a single file.
func mergeMapping(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, val := src.Content[i], src.Content[i+1]
		if j := findKey(dst, key.Value); j >= 0 {
			dv := dst.Content[j+1]
			switch {
			case isNull(val):
				// nothing to contribute
			case isMapping(dv) && isMapping(val):
				mergeMapping(dv, val)
			case isSequence(dv) && isSequence(val):
				dv.Content = append(dv.Content, val.Content...)
			default:
				dst.Content[j+1] = val
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
