// Package safefile provides bounded reads of explicitly named local artifacts.
package safefile

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// ReadRegular opens without following a final symlink and without blocking on
// a FIFO substituted by a concurrent writer. All checks and reads use one FD.
// The containing directory must be trusted by the caller.
func ReadRegular(path string, maxBytes int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, errors.New("artifact must be a regular file, not a symlink")
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("artifact must be a regular file, not a symlink or device")
	}
	if maxBytes < 1 || info.Size() > maxBytes {
		return nil, errors.New("artifact exceeds its byte limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("artifact exceeds its byte limit")
	}
	return data, nil
}
