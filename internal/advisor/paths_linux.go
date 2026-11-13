package advisor

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Hold every parent directory by descriptor. Renaming it or replacing its
// pathname with a symlink cannot redirect the next lookup outside that parent.
// O_PATH observes metadata only, including for unreadable files and FIFOs.
func presentWithoutSymlinks(root, relative string, wantDir bool) (bool, error) {
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	parts := strings.Split(relative, "/")
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false, errors.New("invalid fixed marker path")
		}
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		_ = unix.Close(fd)
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return false, err
		}
		kind := stat.Mode & unix.S_IFMT
		if i < len(parts)-1 || wantDir {
			if kind != unix.S_IFDIR {
				return false, nil
			}
		} else {
			return kind == unix.S_IFREG, nil
		}
	}
	return true, nil
}
