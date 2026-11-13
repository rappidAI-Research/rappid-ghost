//go:build !linux

package advisor

import "errors"

func presentWithoutSymlinks(root, relative string, wantDir bool) (bool, error) {
	return false, errors.New("descriptor-safe project diagnostics require Linux; this host platform is not qualified")
}
