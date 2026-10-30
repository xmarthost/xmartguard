package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The agent runs as root but acts on files in folders hosting accounts
// own, often long after the path was recorded. By then a folder on the
// path may be a link the account planted (public_html -> /etc), so a plain
// os.Rename, os.Remove or os.Chmod would act outside the account. Every
// file action therefore opens the folder holding the file one component at
// a time without following links, and acts relative to that pinned folder
// handle with the *at system calls. Only links owned by root are followed
// (an account cannot create one; servers link /home to /home2 this way),
// and their targets are walked by the same rules.

// ErrLinkInPath: a folder on a finding's path is a link an account controls.
var ErrLinkInPath = errors.New("a folder on the path is a link; refusing to follow it")

const dirFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC

// openDir opens dir as an O_PATH handle without following links that are
// not root's. With create, missing folders are made (mode 0755).
func openDir(dir string, create bool) (int, error) {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) {
		return -1, &os.PathError{Op: "open", Path: dir, Err: errors.New("not an absolute path")}
	}
	fd, err := unix.Open("/", dirFlags, 0)
	if err != nil {
		return -1, err
	}
	todo, links := strings.Split(dir, "/"), 0
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		if c == "" || c == "." {
			continue
		}
		nfd, err := unix.Openat(fd, c, dirFlags|unix.O_NOFOLLOW, 0)
		if err == unix.ENOENT && create && c != ".." {
			if err = unix.Mkdirat(fd, c, 0o755); err == nil || err == unix.EEXIST {
				nfd, err = unix.Openat(fd, c, dirFlags|unix.O_NOFOLLOW, 0)
			}
		}
		if err != nil {
			var st unix.Stat_t
			if unix.Fstatat(fd, c, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				buf := make([]byte, unix.PathMax)
				n, rerr := unix.Readlinkat(fd, c, buf)
				if st.Uid != 0 || rerr != nil || links >= 40 {
					unix.Close(fd)
					return -1, &os.PathError{Op: "open", Path: dir, Err: ErrLinkInPath}
				}
				links++
				target := string(buf[:n])
				if strings.HasPrefix(target, "/") {
					root, err := unix.Open("/", dirFlags, 0)
					if err != nil {
						unix.Close(fd)
						return -1, err
					}
					unix.Close(fd)
					fd = root
				}
				todo = append(strings.Split(target, "/"), todo...)
				continue
			}
			unix.Close(fd)
			return -1, &os.PathError{Op: "open", Path: dir, Err: err}
		}
		unix.Close(fd)
		fd = nfd
	}
	return fd, nil
}

// pinned is the folder holding a file, opened by openDir, and the file's
// name in it.
type pinned struct {
	dir        int
	name, path string
}

// pin opens the folder holding path (creating missing folders with create).
func pin(path string, create bool) (*pinned, error) {
	path = filepath.Clean(path)
	name := filepath.Base(path)
	if name == "/" || name == "." || name == ".." {
		return nil, &os.PathError{Op: "open", Path: path, Err: errors.New("not a file path")}
	}
	fd, err := openDir(filepath.Dir(path), create)
	if err != nil {
		return nil, err
	}
	return &pinned{dir: fd, name: name, path: path}, nil
}

func (p *pinned) Close() { unix.Close(p.dir) }

// lstat stats the file itself (a link is not followed).
func (p *pinned) lstat() (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(p.dir, p.name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

// open opens the file for reading: never through a link, never a FIFO or
// device (which could block or never end).
func (p *pinned) open() (*os.File, error) {
	fd, err := unix.Openat(p.dir, p.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p.path, Err: err}
	}
	f := os.NewFile(uintptr(fd), p.path)
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: p.path, Err: errors.New("not a regular file")}
	}
	return f, nil
}

// remove unlinks the file (a link itself, never its target).
func (p *pinned) remove() error {
	err := unix.Unlinkat(p.dir, p.name, 0)
	if err == unix.EPERM {
		err = p.unlocked(func() error { return unix.Unlinkat(p.dir, p.name, 0) })
	}
	if err != nil {
		return &os.PathError{Op: "remove", Path: p.path, Err: err}
	}
	return nil
}

// lockFlags are the inode flags that stop a file being moved or removed
// even by root: kits set them on their shells (chattr +i) so cleanup
// fails, and on the folder holding them.
const lockFlags = 0x10 | 0x20 // FS_IMMUTABLE_FL, FS_APPEND_FL (linux/fs.h)

// clearLock clears fd's lock flags; it returns the old flags, or -1 when
// none were set (or they could not be read).
func clearLock(fd int) int {
	old, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil || old&lockFlags == 0 {
		return -1
	}
	if unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, old&^lockFlags) != nil {
		return -1
	}
	return old
}

// unlocked runs op again with the file's lock flags cleared (they stay
// cleared: the file is going away) and its folder's cleared for the time
// of op only (an administrator may have locked the folder on purpose).
func (p *pinned) unlocked(op func() error) error {
	locked := false
	if f, err := p.open(); err == nil {
		locked = clearLock(int(f.Fd())) >= 0
		f.Close()
	}
	// (p.dir is an O_PATH handle; ioctl needs one opened for reading.)
	if dfd, err := unix.Openat(p.dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
		defer unix.Close(dfd)
		if old := clearLock(dfd); old >= 0 {
			locked = true
			defer unix.IoctlSetPointerInt(dfd, unix.FS_IOC_SETFLAGS, old)
		}
	}
	if !locked {
		return unix.EPERM
	}
	return op()
}

// setOwner gives the file its owner (uid < 0: unchanged) and mode through
// an open handle, so a link swapped in meanwhile is refused, not followed.
func (p *pinned) setOwner(uid, gid int, mode os.FileMode) error {
	f, err := p.open()
	if err != nil {
		return err
	}
	defer f.Close()
	if uid >= 0 {
		_ = f.Chown(uid, gid)
	}
	return f.Chmod(mode)
}

// write puts src at the pinned name with owner uid/gid (uid < 0: root's)
// and mode, through a temporary file with a random name created
// exclusively. With replace an existing file is replaced; otherwise an
// existing name is an error (os.ErrExist).
func (p *pinned) write(src io.Reader, uid, gid int, mode os.FileMode, replace bool) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ".xg-" + hex.EncodeToString(rnd[:]) + ".tmp"
	fd, err := unix.Openat(p.dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "create", Path: p.path, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = io.Copy(f, src)
	if err == nil && uid >= 0 {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = p.renameIn(tmp, replace)
	}
	if err != nil {
		_ = unix.Unlinkat(p.dir, tmp, 0)
		return err
	}
	return nil
}

// renameIn renames tmp (in the pinned folder) to the pinned name.
func (p *pinned) renameIn(tmp string, replace bool) error {
	if replace {
		return wrapRename(p.path, unix.Renameat(p.dir, tmp, p.dir, p.name))
	}
	err := unix.Renameat2(p.dir, tmp, p.dir, p.name, unix.RENAME_NOREPLACE)
	if err == unix.EINVAL || err == unix.ENOSYS {
		// The file system cannot rename without replacing: a hard link
		// also fails when the name exists.
		if err = unix.Linkat(p.dir, tmp, p.dir, p.name, 0); err == nil {
			_ = unix.Unlinkat(p.dir, tmp, 0)
		}
	}
	return wrapRename(p.path, err)
}

func wrapRename(path string, err error) error {
	if err == nil {
		return nil
	}
	if err == unix.EEXIST {
		return &os.PathError{Op: "rename", Path: path, Err: os.ErrExist}
	}
	return &os.PathError{Op: "rename", Path: path, Err: err}
}

// putFrom moves a root-held file (src, in quarantine) to the pinned name
// with owner uid/gid and mode; replace allows replacing an existing file.
// Across file systems the content is copied and src removed.
func (p *pinned) putFrom(src string, uid, gid int, mode os.FileMode, replace bool) error {
	// Give the quarantined copy its owner and mode first: once moved, the
	// file is in the account's folder and is not touched again by path.
	if uid >= 0 {
		_ = os.Lchown(src, uid, gid)
	}
	if err := os.Chmod(src, mode); err != nil {
		return err
	}
	var err error
	if replace {
		err = unix.Renameat(unix.AT_FDCWD, src, p.dir, p.name)
	} else {
		err = unix.Renameat2(unix.AT_FDCWD, src, p.dir, p.name, unix.RENAME_NOREPLACE)
	}
	if err == nil {
		return nil
	}
	if err == unix.EEXIST {
		err = wrapRename(p.path, err)
	} else {
		var in *os.File
		if in, err = os.Open(src); err == nil {
			err = p.write(in, uid, gid, mode, replace)
			in.Close()
			if err == nil {
				return os.Remove(src)
			}
		}
	}
	// Still in quarantine: keep it root's and unreadable.
	_ = os.Chmod(src, 0)
	_ = os.Lchown(src, 0, 0)
	return err
}

// takeTo moves the pinned file into dst (a root-only quarantine path).
// A name that is no longer a regular file is left where it is.
func (p *pinned) takeTo(dst string) error {
	st, err := p.lstat()
	if err != nil {
		return &os.PathError{Op: "lstat", Path: p.path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("not a regular file")
	}
	err = unix.Renameat(p.dir, p.name, unix.AT_FDCWD, dst)
	if err == unix.EPERM {
		err = p.unlocked(func() error { return unix.Renameat(p.dir, p.name, unix.AT_FDCWD, dst) })
	}
	if err == nil {
		if fi, lerr := os.Lstat(dst); lerr != nil || !fi.Mode().IsRegular() {
			// Swapped between the check and the move: put it back.
			_ = unix.Renameat2(unix.AT_FDCWD, dst, p.dir, p.name, unix.RENAME_NOREPLACE)
			return errors.New("not a regular file")
		}
		return nil
	}
	if err != unix.EXDEV {
		return &os.PathError{Op: "rename", Path: p.path, Err: err}
	}
	in, err := p.open()
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return p.remove()
}

// OpenFile opens a file an account may control for reading as root: no
// link is followed on the way or at the end, and only a regular file is
// opened (a FIFO or device could block or never end).
func OpenFile(path string) (*os.File, error) {
	p, err := pin(path, false)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	return p.open()
}

// removeFile unlinks a file an account may control through its pinned
// folder (a link itself is removed, never what it points to).
func removeFile(path string) error {
	p, err := pin(path, false)
	if err != nil {
		return err
	}
	defer p.Close()
	return p.remove()
}

// ReadFileLimit reads at most limit bytes of a file through OpenFile; the
// bool reports whether the file was longer.
func ReadFileLimit(path string, limit int64) ([]byte, bool, error) {
	f, err := OpenFile(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > limit {
		return b[:limit], true, nil
	}
	return b, false, nil
}

// openScanned opens a file the scan stat'ed: a link put at the name since
// is not followed, a FIFO or device is refused (opened non-blocking, so it
// cannot hang a worker), and info, when given, must still be the same file.
func openScanned(path string, info fs.FileInfo) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err == nil && info != nil {
		a, ok1 := st.Sys().(*syscall.Stat_t)
		b, ok2 := info.Sys().(*syscall.Stat_t)
		if ok1 && ok2 && (a.Dev != b.Dev || a.Ino != b.Ino) {
			err = errors.New("the file changed while it was scanned")
		}
	}
	if err != nil {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return f, nil
}

// readScanned reads at most limit bytes of a file through openScanned.
func readScanned(path string, info fs.FileInfo, limit int64) ([]byte, error) {
	f, err := openScanned(path, info)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
