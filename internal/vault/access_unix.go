//go:build unix

package vault

import "golang.org/x/sys/unix"

// canWrite は path に書き込み権限があるかを返す (読み取り専用のファイルシステムも false)。
func canWrite(path string) bool {
	return unix.Access(path, unix.W_OK) == nil
}
