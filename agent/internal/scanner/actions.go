package scanner

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

type row struct {
	path, status, qpath string
	mode, uid, gid      int
}

func (s *Scanner) load(id int64) (row, error) {
	var r row
	err := s.DB.QueryRow(`SELECT path, status, qpath, orig_mode, orig_uid, orig_gid FROM findings WHERE id = ?`, id).
		Scan(&r.path, &r.status, &r.qpath, &r.mode, &r.uid, &r.gid)
	if errors.Is(err, sql.ErrNoRows) {
		return r, errors.New("finding not found")
	}
	return r, err
}

func (s *Scanner) setStatus(id int64, status, qpath string) error {
	_, err := s.DB.Exec(`UPDATE findings SET status = ?, qpath = ?, updated_at = ? WHERE id = ?`, status, qpath, store.Now(), id)
	return err
}

// moveFile renames, falling back to copy+remove across filesystems.
func moveFile(src, dst string, mode os.FileMode) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
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
	return os.Remove(src)
}

// Quarantine moves a detected (or disabled) file into the root-only quarantine.
func (s *Scanner) Quarantine(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	if r.status != "detected" && r.status != "disabled" && r.status != "restored" {
		return fmt.Errorf("cannot quarantine a %s file", r.status)
	}
	st, err := os.Lstat(r.path)
	if err != nil {
		return fmt.Errorf("file no longer exists: %s", r.path)
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	dir := QuarantineDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	dst := filepath.Join(dir, strconv.FormatInt(id, 10)+".q")
	if err := moveFile(r.path, dst, 0o000); err != nil {
		return err
	}
	_ = os.Chmod(dst, 0o000)
	_ = os.Chown(dst, 0, 0)
	return s.setStatus(id, "quarantined", dst)
}

// Disable removes all permissions (chmod 000) but leaves the file in place.
func (s *Scanner) Disable(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	if r.status != "detected" && r.status != "restored" {
		return fmt.Errorf("cannot disable a %s file", r.status)
	}
	if err := os.Chmod(r.path, 0o000); err != nil {
		return err
	}
	return s.setStatus(id, "disabled", "")
}

// Restore puts a quarantined file back (never overwriting) or re-enables a
// disabled one, with its original owner and permissions.
func (s *Scanner) Restore(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	switch r.status {
	case "quarantined":
		if _, err := os.Lstat(r.path); err == nil {
			return fmt.Errorf("a file already exists at %s; move it away first", r.path)
		}
		if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
			return err
		}
		if err := moveFile(r.qpath, r.path, os.FileMode(r.mode)); err != nil {
			return err
		}
	case "disabled":
	default:
		return fmt.Errorf("cannot restore a %s file", r.status)
	}
	if r.uid >= 0 {
		_ = os.Lchown(r.path, r.uid, r.gid)
	}
	if err := os.Chmod(r.path, os.FileMode(r.mode)); err != nil {
		return err
	}
	return s.setStatus(id, "restored", "")
}

// Delete permanently removes the file (from quarantine or its location).
func (s *Scanner) Delete(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	target := r.path
	switch r.status {
	case "quarantined":
		target = r.qpath
	case "detected", "disabled", "restored", "ignored":
	default:
		return fmt.Errorf("cannot delete a %s file", r.status)
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.setStatus(id, "deleted", "")
}

// Ignore marks a finding as a false positive and whitelists the file path.
func (s *Scanner) Ignore(id int64) (string, error) {
	r, err := s.load(id)
	if err != nil {
		return "", err
	}
	if r.status == "quarantined" {
		if err := s.Restore(id); err != nil {
			return "", err
		}
	} else if r.status == "disabled" {
		if err := s.Restore(id); err != nil {
			return "", err
		}
	}
	return r.path, s.setStatus(id, "ignored", "")
}
