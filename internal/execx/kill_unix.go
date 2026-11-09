//go:build unix

package execx

import (
	"os/exec"
	"syscall"
	"time"
)

// configureKill starts the child in its own process group and, on timeout or
// cancellation, kills the whole group so grandchildren cannot keep the
// output pipes open.
func configureKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
}
