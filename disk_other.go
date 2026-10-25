//go:build !linux && !windows

package main

import "errors"

// diskUsage is not implemented here; /api/system then reports the disk as unavailable.
func diskUsage(string) (free, total uint64, err error) {
	return 0, 0, errors.New("disk usage is not supported on this platform")
}
