//go:build unix

package probes

import (
	"fmt"
	"syscall"
)

// OSStatfs is the StatfsFunc of the host.
func OSStatfs(path string) (Statfs, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return Statfs{}, err
	}
	if int64(s.Bsize) < 0 {
		return Statfs{}, fmt.Errorf("statfs %s: negative block size", path)
	}
	return Statfs{
		BlockSize: uint64(s.Bsize),
		Blocks:    uint64(s.Blocks),
		Bfree:     uint64(s.Bfree),
		Bavail:    uint64(s.Bavail),
		Files:     uint64(s.Files),
		Ffree:     uint64(s.Ffree),
	}, nil
}
