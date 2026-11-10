//go:build !unix

package probes

import "errors"

// OSStatfs is not available on this platform; tests inject their own
// StatfsFunc.
func OSStatfs(path string) (Statfs, error) {
	return Statfs{}, errors.New("statfs is not available on this platform")
}
