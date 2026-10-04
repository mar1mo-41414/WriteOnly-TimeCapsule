//go:build !unix

package vault

// canWrite は unix 以外 (未対応OS) では常に true を返す (実際の操作時のエラーに任せる)。
func canWrite(string) bool { return true }
