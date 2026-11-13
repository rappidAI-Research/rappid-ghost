package runtime

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
)

// Snapshot the running executable, not its mutable installation pathname.
// A static Linux executable is necessary for the closed Alpine environments.
func validateBrokerExecutable() error {
	input, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer input.Close()
	executable, err := elf.NewFile(input)
	if err != nil {
		return err
	}
	for _, p := range executable.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("broker requires a static Linux Ghost executable; use make build")
		}
	}
	return nil
}
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

// Verify the actual created boundary before untrusted exec. A dropped/mutable
// broker mount or unexpected network would invalidate mediation guarantees.
func (d *DockerRuntime) verifyBrokerBoundary(ctx context.Context, id string, request RunRequest) error {
	command := exec.CommandContext(ctx, d.binary, "inspect", "--format", "{{json .}}", id)
	var output oomOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return errors.New("inspect broker isolation failed")
	}
	return validateBrokerBoundary(output.Bytes(), request.brokerDirectory, request.brokerHelper)
}
func validateBrokerBoundary(data []byte, directory, helper string) error {
	var inspected struct {
		HostConfig struct {
			NetworkMode string
			Mounts      []struct {
				Type, Source, Target string
				ReadOnly             bool
				BindOptions          struct{ NonRecursive bool }
			}
		}
		Mounts []struct {
			Type, Source, Destination string
			RW                        bool
		}
	}
	if json.Unmarshal(data, &inspected) != nil || inspected.HostConfig.NetworkMode != "none" {
		return errors.New("broker requires verified Docker network=none")
	}
	for destination, source := range map[string]string{"/run/ghost-broker": directory, "/run/ghost-helper": helper} {
		count, settings := 0, 0
		for _, mount := range inspected.Mounts {
			if mount.Destination == destination {
				count++
				if mount.Type != "bind" || mount.Source != source || mount.RW {
					return errors.New("invalid broker bind exposure")
				}
			}
		}
		for _, mount := range inspected.HostConfig.Mounts {
			if mount.Target == destination {
				settings++
				if mount.Type != "bind" || mount.Source != source || !mount.ReadOnly || !mount.BindOptions.NonRecursive {
					return errors.New("broker bind recursion or write protection not retained")
				}
			}
		}
		if count != 1 || settings != 1 {
			return errors.New("broker mount missing or duplicated")
		}
	}
	return nil
}
