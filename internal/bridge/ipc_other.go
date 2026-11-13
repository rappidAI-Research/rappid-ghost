//go:build !linux

package bridge

import "errors"

func protectBridge() error   { return errors.New("broker bridge requires qualified Linux isolation") }
func ExecAgent([]string) int { return 1 }
