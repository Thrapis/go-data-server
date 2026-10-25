//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var procGetDiskFreeSpaceEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// diskUsage returns the space available to the caller and the total size of the volume
// holding dir. Only used when developing on Windows; the server itself runs on Linux.
func diskUsage(dir string) (free, total uint64, err error) {
	path, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	var avail, size, totalFree uint64
	r, _, callErr := procGetDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&avail)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, 0, callErr
	}
	return avail, size, nil
}
