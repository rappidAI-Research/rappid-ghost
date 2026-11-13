package runtime

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
)

// Snapshot the running executable, not its mutable installation pathname.
// A static Linux executable is necessary for the closed Alpine environments.
func prepareBrokerHelper(request *RunRequest) error {
	if goruntime.GOOS != "linux" {
		return errors.New("broker integration currently requires qualified native Linux Docker")
	}
	input, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer input.Close()
	executable, err := elf.NewFile(input)
	if err != nil {
		return errors.New("broker helper must be a static Linux ELF executable")
	}
	for _, p := range executable.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("broker helper requires a static Ghost binary; rebuild using make build (CGO_ENABLED=0)")
		}
	}
	if _, err = input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	target := filepath.Join(request.SessionDir, "broker-helper")
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		return err
	}
	size, copyErr := io.Copy(output, io.LimitReader(input, 64*1024*1024+1))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil || size > 64*1024*1024 {
		os.Remove(target)
		return errors.New("snapshot bounded broker helper failed")
	}
	request.brokerHelper = target
	return nil
}

func (d *DockerRuntime) startSessionBroker(ctx context.Context, request *RunRequest, sentinel *sentinelProcess) (func() error, error) {
	if !request.Broker.Enabled() {
		return nil, nil
	}
	options := broker.Options{Audit: request.BrokerAudit, Check: func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := d.RecoveredSecurityState(ctx, request.SessionDir)
		if err != nil {
			return err
		}
		if state.IsContained() {
			return errors.New("session contained")
		}
		return nil
	}}
	if sentinel != nil {
		options.Fence = sentinel.barrier
	}
	server, err := broker.New(ctx, request.Broker, options)
	if err != nil {
		return nil, fmt.Errorf("prepare session broker (check endpoint identity and explicit credential_env): %w", err)
	}
	dir, close, err := server.ServeUnix(request.SessionID)
	if err != nil {
		server.Close()
		return nil, err
	}
	request.brokerDirectory = dir
	request.Command = append([]string{"/run/ghost-helper", "_broker-bridge"}, request.Command...)
	return close, nil
}
