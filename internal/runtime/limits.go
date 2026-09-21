package runtime

import (
	"errors"
	"fmt"
	"time"
)

// Limits are mandatory, per-container ceilings, not reservations of host
// capacity. A nil RunRequest.Limits selects defaults; explicit zeros are invalid.
type Limits struct {
	MemoryMiB      int64 `yaml:"memory_mib"`
	CPUMillis      int64 `yaml:"cpu_millis"`
	PIDs           int64 `yaml:"pids"`
	TimeoutSeconds int64 `yaml:"timeout_seconds"`
	GraceSeconds   int64 `yaml:"grace_seconds"`
	TmpMiB         int64 `yaml:"tmp_mib"`
}

func DefaultLimits() Limits {
	return Limits{MemoryMiB: 2048, CPUMillis: 1000, PIDs: 256, TimeoutSeconds: 3600, GraceSeconds: 5, TmpMiB: 64}
}

func (l Limits) Validate() error {
	for _, field := range []struct {
		name            string
		value, min, max int64
	}{
		{"memory_mib", l.MemoryMiB, 64, 65536},
		{"cpu_millis", l.CPUMillis, 100, 8000},
		{"pids", l.PIDs, 16, 4096},
		{"timeout_seconds", l.TimeoutSeconds, 1, 86400},
		{"grace_seconds", l.GraceSeconds, 1, 30},
		{"tmp_mib", l.TmpMiB, 1, 1024},
	} {
		if field.value < field.min || field.value > field.max {
			return fmt.Errorf("runtime.limits.%s must be between %d and %d", field.name, field.min, field.max)
		}
	}
	if l.TmpMiB > l.MemoryMiB {
		return errors.New("runtime.limits.tmp_mib must not exceed memory_mib")
	}
	return nil
}

func requestLimits(request RunRequest) Limits {
	if request.Limits == nil {
		return DefaultLimits()
	}
	return *request.Limits
}

var ErrSessionTimeout = errors.New("maximum session runtime reached")

// ResourceEvidence contains only host/Docker observations. Exit status 137,
// guest output, and failed allocations alone are never evidence of an OOM.
type ResourceEvidence struct {
	Kind       string
	DetectedAt time.Time
	Limit      int64
	Observed   int64
}

const (
	ResourceTimeout = "session_timeout"
	ResourceOOM     = "oom_termination"
	ResourcePIDs    = "process_limit_reached"
)

func (e ResourceEvidence) Validate() error {
	if e.DetectedAt.IsZero() || e.Limit <= 0 {
		return errors.New("invalid runtime resource evidence")
	}
	switch e.Kind {
	case ResourceTimeout, ResourceOOM:
		if e.Observed != 0 {
			return errors.New("unexpected resource observation")
		}
	case ResourcePIDs:
		if e.Observed < e.Limit {
			return errors.New("process limit evidence is below the boundary")
		}
	default:
		return errors.New("unknown runtime resource evidence kind")
	}
	return nil
}
