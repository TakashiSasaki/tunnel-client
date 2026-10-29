// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TAKASHI SASAKI <takashi316@gmail.com>

package hostcredentials

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func defaultPath(_ func(string) string) (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return "", errors.New("cannot locate the current user's LocalAppData")
	}
	return filepath.Join(base, "TakashiSasaki", "HostMonitor", "credentials.enc"), nil
}

type dpapiEncryption struct{}

func (dpapiEncryption) Name() string                { return "dpapi-user" }
func (dpapiEncryption) Check(context.Context) error { return nil }
func platformEncryption() encryption                { return dpapiEncryption{} }

func dpapi(data []byte, decrypt bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty encrypted credential data")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	entropy := []byte("TakashiSasaki/HostMonitor/credentials/v1")
	contextBlob := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&in, nil, &contextBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		// No CRYPTPROTECT_LOCAL_MACHINE: bind to the current OS user.
		err = windows.CryptProtectData(&in, nil, &contextBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, errors.New("DPAPI operation failed for the current Windows user")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Size > maxFileSize {
		return nil, errors.New("DPAPI result exceeds size limit")
	}
	source := unsafe.Slice(out.Data, int(out.Size))
	copy := append([]byte(nil), source...)
	clear(source)
	return copy, nil
}
func (dpapiEncryption) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return dpapi(data, false)
}
func (dpapiEncryption) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return dpapi(data, true)
}

func currentSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", errors.New("cannot identify the current Windows user")
	}
	return user.User.Sid.String(), nil
}

func privateAttributes(directory bool) (*windows.SecurityAttributes, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + inherit + ";FA;;;" + sid + ")(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)")
	if err != nil {
		return nil, errors.New("cannot create credential access policy")
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func makePrivateDirs(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("credentials directory must be a directory, not a link")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect credentials directory")
	}
	if err := makePrivateDirs(filepath.Dir(dir)); err != nil {
		return err
	}
	attrs, err := privateAttributes(true)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(name, attrs)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return makePrivateDirs(dir)
	}
	return err
}

func openPrivateRead(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, errors.New("credentials must be a regular file without reparse points or extra links")
	}
	return os.NewFile(uintptr(h), path), nil
}

func createPrivateFile(path string) (*os.File, error) {
	attrs, err := privateAttributes(false)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func publishFile(tmp, path string, create bool) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if !create {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(from, to, flags)
}

func lockStore(ctx context.Context, path string) (func(), error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(strings.ToLower(path)))
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf("Global\\TakashiSasaki.HostMonitor.%s.%x", sid, digest))
	attrs, err := privateAttributes(false)
	if err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	h, err := windows.CreateMutex(attrs, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		runtime.UnlockOSThread()
		return nil, errors.New("cannot create credentials lock")
	}
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(h)
			runtime.UnlockOSThread()
			return nil, err
		}
		result, err := windows.WaitForSingleObject(h, 25)
		if err != nil {
			windows.CloseHandle(h)
			runtime.UnlockOSThread()
			return nil, errors.New("cannot acquire credentials lock")
		}
		if result == windows.WAIT_OBJECT_0 || result == windows.WAIT_ABANDONED {
			return func() { windows.ReleaseMutex(h); windows.CloseHandle(h); runtime.UnlockOSThread() }, nil
		}
	}
}
