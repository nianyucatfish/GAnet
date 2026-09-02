//go:build !windows && !darwin

package main

import "errors"

func autostartInstall() error {
	return errors.New("autostart is supported on Windows and macOS only")
}

func autostartRemove() error {
	return errors.New("autostart is supported on Windows and macOS only")
}
