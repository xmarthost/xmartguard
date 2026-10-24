package scanner

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

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

// ErrFileGone: the file was removed or renamed before an action on it.
var ErrFileGone = errors.New("file no longer exists")

// NoteGone explains a finding whose file vanished before quarantine.
const NoteGone = "The file was gone before it could be quarantined (renamed or removed, as malware does with temporary files); the file it became is scanned on its own"

func (s *Scanner) setStatus(id int64, status, qpath string) error {
	_, err := s.DB.Exec(`UPDATE findings SET status = ?, qpath = ?, note = '', updated_at = ? WHERE id = ?`, status, qpath, store.Now(), id)
	return err
}

// Quarantine moves a detected (or disabled) file into the root-only quarantine.
func (s *Scanner) Quarantine(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	if r.status != "detected" && r.status != "disabled" && r.status != "restored" && r.status != StatusAIRestored {
		return fmt.Errorf("cannot quarantine a %s file", r.status)
	}
	p, err := pin(r.path, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrFileGone, r.path)
		}
		return err
	}
	defer p.Close()
	st, err := p.lstat()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFileGone, r.path)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK && (r.status == "detected" || r.status == "restored" || r.status == StatusAIRestored) {
		return s.QuarantineLink(id) // a link to another account
	}
	dir := QuarantineDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	dst := filepath.Join(dir, strconv.FormatInt(id, 10)+".q")
	if err := p.takeTo(dst); err != nil {
		return err
	}
	_ = os.Chmod(dst, 0o000)
	_ = os.Chown(dst, 0, 0)
	return s.setStatus(id, "quarantined", dst)
}

// LinkPrefix marks a quarantined symbolic link: the link was removed and
// qpath keeps its target, so Restore can make it again.
const LinkPrefix = "link:"

// QuarantineLink removes a symbolic link to another account's files (never
// its target) and records where it pointed.
func (s *Scanner) QuarantineLink(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	if r.status != "detected" && r.status != "restored" && r.status != StatusAIRestored {
		return fmt.Errorf("cannot quarantine a %s link", r.status)
	}
	p, err := pin(r.path, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrFileGone, r.path)
		}
		return err
	}
	defer p.Close()
	st, err := p.lstat()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFileGone, r.path)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return errors.New("not a symbolic link")
	}
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(p.dir, p.name, buf)
	if err != nil {
		return &os.PathError{Op: "readlink", Path: r.path, Err: err}
	}
	if err := p.remove(); err != nil {
		return err
	}
	return s.setStatus(id, "quarantined", LinkPrefix+string(buf[:n]))
}

// Disable removes all permissions (chmod 000) but leaves the file in place.
func (s *Scanner) Disable(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	if r.status != "detected" && r.status != "restored" && r.status != StatusAIRestored {
		return fmt.Errorf("cannot disable a %s file", r.status)
	}
	p, err := pin(r.path, false)
	if err != nil {
		return err
	}
	defer p.Close()
	if err := p.setOwner(-1, -1, 0o000); err != nil {
		return err
	}
	return s.setStatus(id, "disabled", "")
}

// Restore puts a quarantined file back (never overwriting) or re-enables a
// disabled one, with its original owner and permissions. The folders on
// the path are opened without following links an account planted.
func (s *Scanner) Restore(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	mode := os.FileMode(r.mode)
	switch {
	case r.status == "quarantined" && strings.HasPrefix(r.qpath, LinkPrefix):
		p, err := pin(r.path, true)
		if err != nil {
			return err
		}
		defer p.Close()
		if err := unix.Symlinkat(strings.TrimPrefix(r.qpath, LinkPrefix), p.dir, p.name); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("a file already exists at %s; move it away first", r.path)
			}
			return &os.PathError{Op: "symlink", Path: r.path, Err: err}
		}
		if r.uid >= 0 {
			_ = unix.Fchownat(p.dir, p.name, r.uid, r.gid, unix.AT_SYMLINK_NOFOLLOW)
		}
		return s.setStatus(id, "restored", "")
	}
	switch r.status {
	case "quarantined":
		p, err := pin(r.path, true)
		if err != nil {
			return err
		}
		defer p.Close()
		if _, err := p.lstat(); err == nil {
			return fmt.Errorf("a file already exists at %s; move it away first", r.path)
		}
		if err := p.putFrom(r.qpath, r.uid, r.gid, mode, false); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("a file already exists at %s; move it away first", r.path)
			}
			return err
		}
	case "disabled":
		p, err := pin(r.path, false)
		if err != nil {
			return err
		}
		defer p.Close()
		if err := p.setOwner(r.uid, r.gid, mode); err != nil {
			return err
		}
	case "trimmed", "cleaned":
		if r.qpath == "" {
			return fmt.Errorf("cannot restore a %s file", r.status)
		}
		// Put the original (untrimmed / unreplaced) file back.
		p, err := pin(r.path, true)
		if err != nil {
			return err
		}
		defer p.Close()
		if err := p.putFrom(r.qpath, r.uid, r.gid, mode, true); err != nil {
			return err
		}
	default:
		return fmt.Errorf("cannot restore a %s file", r.status)
	}
	return s.setStatus(id, "restored", "")
}

// Delete permanently removes the file (from quarantine or its location).
func (s *Scanner) Delete(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	switch r.status {
	case "quarantined":
		if strings.HasPrefix(r.qpath, LinkPrefix) {
			return s.setStatus(id, "deleted", "") // the link is already gone
		}
		if err := os.Remove(r.qpath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return s.setStatus(id, "deleted", "")
	case "detected", "disabled", "restored", "ignored", StatusAIRestored:
	case "trimmed", "cleaned":
		if r.qpath != "" {
			_ = os.Remove(r.qpath) // the original kept in quarantine
		}
	default:
		return fmt.Errorf("cannot delete a %s file", r.status)
	}
	p, err := pin(r.path, false)
	if err == nil {
		err = p.remove()
		p.Close()
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.setStatus(id, "deleted", "")
}

// PruneKept removes the originals kept for trimmed and cleaned files whose
// finding is older than cut (the cleaned file stays live), then the
// findings themselves: retention for them as for quarantined files.
func (s *Scanner) PruneKept(cut int64) int {
	rows, err := s.DB.Query(`SELECT id, qpath FROM findings WHERE status IN ('trimmed','cleaned') AND updated_at < ?`, cut)
	if err != nil {
		return 0
	}
	type kept struct {
		id    int64
		qpath string
	}
	var list []kept
	for rows.Next() {
		var k kept
		if rows.Scan(&k.id, &k.qpath) == nil {
			list = append(list, k)
		}
	}
	rows.Close()
	n := 0
	for _, k := range list {
		if k.qpath != "" {
			if err := os.Remove(k.qpath); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.Log.Warn("retention: remove a kept original", "path", k.qpath, "err", err)
				continue
			}
		}
		if _, err := s.DB.Exec(`DELETE FROM findings WHERE id = ?`, k.id); err == nil {
			n++
		}
	}
	return n
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

// FindingPath returns the original path of a finding (for ownership checks).
func (s *Scanner) FindingPath(id int64) (string, error) {
	r, err := s.load(id)
	return r.path, err
}

// UserWhitelisted reports whether an account is excluded from scanning.
func (s *Scanner) UserWhitelisted(name string) bool {
	for _, u := range s.Settings.Get().Scanner.WhitelistUsers {
		if u == name {
			return true
		}
	}
	return false
}

// ContentPath returns where a finding's content can be read now (the
// quarantine copy for quarantined files) and its status.
func (s *Scanner) ContentPath(id int64) (string, string, error) {
	r, err := s.load(id)
	if err != nil {
		return "", "", err
	}
	if (r.status == "quarantined" || r.status == "trimmed" || r.status == "cleaned") && r.qpath != "" {
		if strings.HasPrefix(r.qpath, LinkPrefix) {
			return "", r.status, errors.New("a removed link has no content")
		}
		return r.qpath, r.status, nil
	}
	return r.path, r.status, nil
}

// Get returns one finding.
func (s *Scanner) Get(id int64) (Finding, error) {
	var f Finding
	err := s.DB.QueryRow(`SELECT id, scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at FROM findings WHERE id = ?`, id).
		Scan(&f.ID, &f.ScanID, &f.Source, &f.Path, &f.Owner, &f.Category, &f.Signature, &f.SHA256, &f.Size, &f.Status, &f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return f, errors.New("finding not found")
	}
	return f, err
}

// RestoreSystemFiles undoes quarantines the current rules would not make:
// root's files and "binaries" that cannot run (relocatable objects such as
// SpamAssassin's compiled rules). A file whose folder is gone (a finished
// build in /var/tmp) is not recreated: its quarantined copy is deleted and
// the finding is marked ignored. Returns the number of findings handled.
func (s *Scanner) RestoreSystemFiles() int {
	rows, err := s.DB.Query(`SELECT id, path, qpath, orig_uid, signature FROM findings WHERE status = 'quarantined'`)
	if err != nil {
		return 0
	}
	type cand struct {
		id          int64
		path, qpath string
	}
	var list []cand
	for rows.Next() {
		var c cand
		var uid int
		var sig string
		if rows.Scan(&c.id, &c.path, &c.qpath, &uid, &sig) != nil {
			continue
		}
		system := uid == 0 && !ScanRootFiles
		if !system && sig == "Binary.ELF.InWebOrTempDir" {
			system = !runnableELF(c.qpath)
		}
		if system {
			list = append(list, c)
		}
	}
	rows.Close()
	n := 0
	for _, c := range list {
		if _, err := os.Stat(filepath.Dir(c.path)); err != nil {
			_ = os.Remove(c.qpath)
			if s.setStatus(c.id, "ignored", "") == nil {
				n++
			}
			continue
		}
		if err := s.Restore(c.id); err != nil {
			s.Log.Warn("could not restore a system file", "path", c.path, "err", err)
			continue
		}
		s.Log.Info("restored a system file quarantined by an older rule", "path", c.path)
		n++
	}
	return n
}

// runnableELF reports whether a file is an ELF program or shared library.
func runnableELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true // unknown: leave it quarantined
	}
	defer f.Close()
	head := make([]byte, 20)
	n, _ := io.ReadFull(f, head)
	t := elfType(head[:n])
	return t == elfExec || t == elfDyn || t == 0
}

// CloseVanished closes open findings whose file is gone (temporary files a
// dropper renamed, files the customer deleted): they wait for no action.
// Symbolic links and findings with a quarantine copy are left alone.
func (s *Scanner) CloseVanished() (int, error) {
	rows, err := s.DB.Query(`SELECT id, path FROM findings WHERE status = 'detected' AND category != 'symlink' AND qpath = ''`)
	if err != nil {
		return 0, err
	}
	var gone []int64
	for rows.Next() {
		var id int64
		var path string
		if rows.Scan(&id, &path) != nil {
			continue
		}
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			gone = append(gone, id)
		}
	}
	rows.Close()
	for _, id := range gone {
		if _, err := s.DB.Exec(`UPDATE findings SET status = 'deleted', note = ?, updated_at = ? WHERE id = ?`, NoteGone, store.Now(), id); err != nil {
			return 0, err
		}
	}
	return len(gone), nil
}

// NoteSafeLink closes a link finding the scanner no longer flags.
const NoteSafeLink = "Closed: the link is the system's or reaches only what its owner may read (no longer flagged)."

// CloseSafeLinks closes open link findings the current rules do not flag
// (root's /home -> /home2 links, ~/logs domlog links, links inside the
// owner's own home: reported before 0.23.8) and those whose link is gone.
func (s *Scanner) CloseSafeLinks() (int, error) {
	rows, err := s.DB.Query(`SELECT id, path FROM findings WHERE status = 'detected' AND category = 'symlink'`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id   int64
		path string
	}
	var open []row
	for rows.Next() {
		var r row
		if rows.Scan(&r.id, &r.path) == nil {
			open = append(open, r)
		}
	}
	rows.Close()
	if len(open) == 0 {
		return 0, nil
	}
	homeMap := homes()
	n := 0
	for _, r := range open {
		note := NoteSafeLink
		status := "cleared"
		if _, err := os.Lstat(r.path); errors.Is(err, fs.ErrNotExist) {
			note, status = NoteGone, "deleted"
		} else if _, bad := InsecureSymlink(r.path, homeMap); bad || err != nil {
			continue
		}
		if _, err := s.DB.Exec(`UPDATE findings SET status = ?, note = ?, updated_at = ? WHERE id = ?`, status, note, store.Now(), r.id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
