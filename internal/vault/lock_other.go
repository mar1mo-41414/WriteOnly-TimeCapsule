//go:build !unix

package vault

import (
	"errors"
	"os"
)

// lockFile は未対応 OS では静かに無防備になるのではなく、未対応であることを
// エラーとして明示する (対応 OS は unix 系統のみ: Makefile の darwin/linux)。
func lockFile(*os.File, bool) error {
	return errors.New("この OS ではコンテナの同時実行ロックに対応していません (対応は macOS / Linux のみです)")
}
