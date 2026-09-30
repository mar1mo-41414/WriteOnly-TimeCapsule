//go:build !unix

package vault

import "os"

// lockFile は unix 以外 (未対応OS) では何もしない。
func lockFile(*os.File, bool) error { return nil }
