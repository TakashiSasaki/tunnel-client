// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func defaultPath(getenv func(string) string) (string, error) {
	base := getenv("XDG_DATA_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home := getenv("HOME")
		if !filepath.IsAbs(home) {
			return "", errors.New("HOME must be absolute when XDG_DATA_HOME is unavailable")
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "host-monitor", "credentials.enc"), nil
}

func platformEncryption() encryption { return systemdEncryption{run: runSystemd} }

func makePrivateDirs(dir string) error { return os.MkdirAll(dir, 0700) }

func openPrivateRead(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("credentials must be an owned regular file with mode 0600 or stricter and one link")
	}
	return f, nil
}

func createPrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func publishFile(tmp, path string, create bool) error {
	if create {
		return unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	}
	return os.Rename(tmp, path)
}

func lockStore(ctx context.Context, path string) (func(), error) {
	fd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot open credentials directory")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		unix.Close(fd)
		return nil, errors.New("credentials directory must be owned by the current user and not writable by group or others")
	}
	// Lock the directory, so no persistent lock file is required. All CLI writers
	// in this directory serialize their read/modify/replace operations.
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			unix.Close(fd)
			return nil, errors.New("cannot lock credentials directory")
		}
		select {
		case <-ctx.Done():
			unix.Close(fd)
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
