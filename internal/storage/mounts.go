package storage

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// os.Root prevents symlink escape but intentionally does not prohibit mount
// traversal. Refuse any mount at/below the selected artifact as an extra guard.
// Mount changes by a privileged host actor remain outside Ghost's threat model.
func refuseSessionMounts(directory, id string) error {
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return errors.New("retention requires native Linux mount validation")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4*1024*1024+1))
	if err != nil || len(data) > 4*1024*1024 {
		return errors.New("retention mount inventory exceeds its bound")
	}
	return checkSessionMounts(data, filepath.Join(canonical, id))
}

func checkSessionMounts(data []byte, target string) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return errors.New("invalid retention mount inventory")
		}
		mount := unescape.Replace(fields[4])
		if mount == target || strings.HasPrefix(mount, target+string(filepath.Separator)) {
			return errors.New("retention refuses a mount point inside the selected session directory")
		}
	}
	return scanner.Err()
}
