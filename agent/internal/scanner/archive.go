package scanner

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path"
	"strings"
)

// Zip archives in web folders often carry web shells (uploaded "plugin"
// zips, backups of an infected site). Members that are scripts are checked
// with the hash database and the analyzer; only confident (virus) results
// are reported, so ordinary plugin and backup archives are left alone.

const (
	maxZipSize    = 25 << 20 // archive on disk
	maxZipEntries = 2000
	maxZipMember  = 4 << 20  // one uncompressed member
	maxZipTotal   = 64 << 20 // all members read
)

// scanZip returns the first confident detection inside a zip archive.
func scanZip(file string, size int64) *Detection {
	if size > maxZipSize {
		return nil
	}
	r, err := zip.OpenReader(file)
	if err != nil {
		return nil
	}
	defer r.Close()
	var total int64
	for i, f := range r.File {
		if i >= maxZipEntries || total >= maxZipTotal {
			break
		}
		if f.FileInfo().IsDir() || f.UncompressedSize64 == 0 || f.UncompressedSize64 > maxZipMember {
			continue
		}
		ext := extOf(path.Base(f.Name))
		if !ScriptExts[ext] {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, maxZipMember+1))
		rc.Close()
		if err != nil || int64(len(content)) > maxZipMember {
			continue
		}
		total += int64(len(content))
		if hdb := activeHashDB(); hdb.SizeKnown(int64(len(content))) {
			label := hdb.LookupSums(int64(len(content)), func() (string, string) {
				h, m := sha256.Sum256(content), md5.Sum(content)
				return hex.EncodeToString(h[:]), hex.EncodeToString(m[:])
			})
			if label != "" {
				return &Detection{CatVirus, "Archive." + label}
			}
		}
		if d := analyze(ext, content); d != nil && d.Category == CatVirus && !inTestsDir(f.Name) {
			return &Detection{CatVirus, "Archive." + d.Signature}
		}
		if d := clamCheck(content); d != nil && d.Category == CatVirus && !inTestsDir(f.Name) {
			return &Detection{CatVirus, "Archive." + d.Signature}
		}
	}
	return nil
}

func inTestsDir(name string) bool {
	n := "/" + strings.ToLower(name)
	return strings.Contains(n, "/tests/") || strings.Contains(n, "/test/")
}
