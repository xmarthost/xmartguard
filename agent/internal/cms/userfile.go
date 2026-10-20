package cms

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Files inside customer accounts are read (and a few written) by the root
// agent. The account controls them: a symlink to another account's file,
// a FIFO that blocks the open forever, or a sparse file of a terabyte that
// os.ReadFile would allocate in full. These helpers open such a file
// without following a symlink (O_NOFOLLOW) and without blocking on a FIFO
// or device (O_NONBLOCK), and accept only a regular file of a bounded size.

// MaxConfigSize bounds the configuration files the agent parses
// (wp-config.php and the like); real ones are a few KB.
const MaxConfigSize = 1 << 20

var errNotRegular = errors.New("not a regular file")

// openUserFile opens a regular file in a customer account; max < 0 means
// no size limit (the caller reads only a bounded part or streams it).
func openUserFile(p string, flag int, max int64) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(p, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: %w", p, errNotRegular)
	}
	if max >= 0 && st.Size() > max {
		f.Close()
		return nil, nil, fmt.Errorf("%s: too large (%d bytes)", p, st.Size())
	}
	return f, st, nil
}

// ReadUserFile reads a regular file of at most max bytes from a customer
// account: never through a symlink, never blocking on a FIFO.
func ReadUserFile(p string, max int64) ([]byte, error) {
	f, _, err := openUserFile(p, os.O_RDONLY, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// ReadAccountFile is ReadUserFile for a file whose content the agent acts
// on (database credentials, wp-config.php it rewrites): the file must also
// belong to the account that owns the folders it sits in (ownedByAccount).
func ReadAccountFile(p string, max int64) ([]byte, error) {
	f, st, err := openUserFile(p, os.O_RDONLY, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := ownedByAccount(p, st); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// ownedByAccount checks a file against the folders above it, up to the
// first one root owns (/home, or the account's home if root owns it): each
// of those folders must be a real folder, not a symlink, owned by the
// file's owner. A symlink or hard link to another account's file, or a
// folder of the account swapped for a symlink to another account's folder,
// does not pass.
func ownedByAccount(p string, st os.FileInfo) error {
	uid, ok := fileUID(st)
	if !ok {
		return nil
	}
	for dir := filepath.Dir(filepath.Clean(p)); ; dir = filepath.Dir(dir) {
		dst, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		du, _ := fileUID(dst)
		if du == 0 {
			return nil // root's folder: the account can not replace it
		}
		if dst.Mode()&os.ModeSymlink != 0 || !dst.IsDir() {
			return fmt.Errorf("%s: %s is a symlink", p, dir)
		}
		if du != uid {
			return fmt.Errorf("%s: not owned by the account of %s", p, dir)
		}
		if dir == "/" || dir == "." {
			return nil
		}
	}
}

func fileUID(st os.FileInfo) (uint32, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return s.Uid, true
}

// writeAccountFile replaces the content of a file ReadAccountFile accepted,
// through a descriptor opened the same safe way (so a symlink put there in
// the meantime is not followed).
func writeAccountFile(p string, b []byte) error {
	f, st, err := openUserFile(p, os.O_WRONLY, -1)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := ownedByAccount(p, st); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(b, 0); err != nil {
		return err
	}
	return f.Close()
}
