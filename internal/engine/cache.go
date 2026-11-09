package engine

import (
	"context"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
)

// cachingRunner remembers the outcome of every command for the duration of
// one run, so that several checks reading the same command (four sshd
// options need one "sshd -T") see one consistent snapshot and the host is
// asked once. Every probe is read-only, so replaying an outcome is safe.
// The cache lives for one Plan.Run and is not safe for concurrent use.
type cachingRunner struct {
	next  execx.Runner
	calls map[string]cached
}

type cached struct {
	res execx.Result
	err error
}

func newCachingRunner(next execx.Runner) *cachingRunner {
	return &cachingRunner{next: next, calls: map[string]cached{}}
}

func (c *cachingRunner) Run(ctx context.Context, argv []string, opts execx.Opts) (execx.Result, error) {
	key := strings.Join(argv, "\x00")
	if hit, ok := c.calls[key]; ok {
		return hit.res, hit.err
	}
	res, err := c.next.Run(ctx, argv, opts)
	c.calls[key] = cached{res, err}
	return res, err
}
