//go:build unix

package vault

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockFile はコンテナにアドバイザリロックを掛ける。exclusive なら排他 (追記用)、そうでなければ共有 (読み出し用)。
// 他の vault が作業中なら、その旨を表示してから終わるまで待つ。
// 同時に2つの add が走ると同じ位置に書いて互いのデータを壊すため、それを防ぐ。
func lockFile(f *os.File, exclusive bool) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		return fmt.Errorf("コンテナのロックに失敗: %w", err)
	}
	fmt.Fprintln(os.Stderr, "他の vault がこのカプセルを使用中です。終わるまで待っています...")
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		return fmt.Errorf("コンテナのロックに失敗: %w", err)
	}
	return nil
}
