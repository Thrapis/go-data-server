//go:build linux

package main

import "syscall"

// diskUsage returns the space available to this (unprivileged) process and the total
// size of the filesystem holding dir.
func diskUsage(dir string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	block := uint64(st.Bsize)
	return uint64(st.Bavail) * block, uint64(st.Blocks) * block, nil
}
