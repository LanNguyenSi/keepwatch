package probes

// Statfs is the usage of one file system as statfs(2) reports it, in units of
// BlockSize bytes for the block counts and in inodes for the file counts.
type Statfs struct {
	BlockSize uint64
	Blocks    uint64 // total blocks
	Bfree     uint64 // free blocks, including those reserved for root
	Bavail    uint64 // free blocks available to unprivileged users
	Files     uint64 // total inodes, 0 when the file system has no fixed count
	Ffree     uint64 // free inodes
}

// StatfsFunc reads the usage of the file system mounted at path.
type StatfsFunc func(path string) (Statfs, error)
