// Package web provides the embedded auditor web UI filesystem.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:auditor
var embedded embed.FS

// AuditorFS returns the embedded auditor web UI filesystem,
// rooted at the auditor/ directory. Returns nil if the
// embedded filesystem is empty.
func AuditorFS() fs.FS {
	sub, err := fs.Sub(embedded, "auditor")
	if err != nil {
		return nil
	}
	return sub
}
