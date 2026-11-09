//go:build unix

package execx

import (
	"os"
	"os/exec"
	"syscall"
)

// configureKill starts the child in its own process group and, on timeout or
// cancellation, kills the whole group so grandchildren cannot keep the
// output pipes open.
func configureKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = waitDelay
}

// killGroup SIGKILLs the child's process group after Run returned, so
// background grandchildren never outlive the call. ESRCH (nobody left) is
// expected and ignored.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func signaled(ps *os.ProcessState) bool {
	if ps == nil {
		return false
	}
	ws, ok := ps.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled()
}
