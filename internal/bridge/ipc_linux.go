//go:build linux

package bridge

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The bridge may dial its single broker Unix endpoint. Agent code must not
// inherit that general IPC ability through live host sockets in the workspace.
func protectBridge() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }

func ExecAgent(argv []string) int {
	if len(argv) == 0 || !guestBoundary() {
		return 1
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		io.WriteString(os.Stderr, "ghost: guest agent executable unavailable in the selected environment; review agent.adapter and runtime.environment\n")
		return 127
	}
	if err = restrictAgentSockets(); err != nil {
		io.WriteString(os.Stderr, "ghost: mandatory agent IPC/socket filter unavailable; qualified Linux seccomp thread synchronization is required; no weaker execution is available\n")
		return 1
	}
	if err = unix.Exec(path, argv, os.Environ()); err != nil {
		return 126
	}
	return 1
}

func restrictAgentSockets() error {
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return errors.New("unsupported socket-filter architecture")
	}
	load := func(offset uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offset}
	}
	eq := func(value uint32, yes, no uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: value, Jt: yes, Jf: no}
	}
	deny := unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}
	filter := []unix.SockFilter{
		load(4), eq(arch, 1, 0), {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		load(0), {Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 0x40000000, Jt: 0, Jf: 1}, {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		// socket(): only IP families. Docker network=none restricts them to the
		// guest loopback bridge. Deny Unix, vsock, netlink, packet and other families.
		load(0), eq(uint32(unix.SYS_SOCKET), 0, 4), load(16), eq(unix.AF_INET, 2, 0), eq(unix.AF_INET6, 1, 0), deny,
		// Anonymous connected Unix STREAM pairs are necessary for agent-internal
		// signal/subprocess channels. They cannot reconnect to a pathname service.
		// Datagram pairs CAN be retargeted, so all other pairs are forbidden.
		load(0), eq(uint32(unix.SYS_SOCKETPAIR), 0, 6), load(16), eq(unix.AF_UNIX, 0, 3), load(24), {Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0xf}, eq(unix.SOCK_STREAM, 1, 0), deny,
		load(0),
	}
	for _, number := range []uint32{unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER} {
		filter = append(filter, eq(number, 0, 1), deny)
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return errors.New("socket filter thread synchronization failed")
	}
	return nil
}
