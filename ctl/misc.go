package ctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/carlmjohnson/requests"
)

func csvReadToMap(in io.Reader) ([]map[string]string, error) {
	r := csv.NewReader(in)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	ret := []map[string]string{}
	keys := []string{}
	for k, v := range records {
		if k == 0 {
			keys = v
			continue
		}
		item := map[string]string{}
		if len(keys) != len(v) {
			continue
		}
		for i, j := range v {
			item[keys[i]] = j
		}
		ret = append(ret, item)
	}
	return ret, nil
}

func getBody(url string) ([]byte, error) {
	var buf bytes.Buffer
	err := requests.URL(url).
		ToBytesBuffer(&buf).Fetch(context.Background())
	if err != nil {
		return nil, fmt.Errorf("get remote csv fail: %w", err)
	}
	return buf.Bytes(), nil
}

func getChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// readUniqueDirectoryEntries is like os.ReadDir but omits
// symlinks that point within the directory.
func readUniqueDirectoryEntries(dir string) ([]fs.DirEntry, error) { //nolint:unused
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	uniq := files[:0]
	for _, f := range files {
		if !isSameDirSymlink(f, dir) {
			uniq = append(uniq, f)
		}
	}
	return uniq, nil
}

// isSameDirSymlink reports whether fi in dir is a symlink with a
// target not containing a slash.
func isSameDirSymlink(f fs.DirEntry, dir string) bool { //nolint:unused
	if f.Type()&fs.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(filepath.Join(dir, f.Name()))
	return err == nil && !strings.Contains(target, "/")
}
