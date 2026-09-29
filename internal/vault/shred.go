package vault

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// ShredPasses は Shred が乱数で上書きする回数。
const ShredPasses = 3

// Shred はファイルを乱数で複数回上書きし、ランダムな名前にリネームしてから削除する
// (GNU shred -u 相当。macOS には shred が無いため自前で実装している)。
//
// 注意: SSD (APFS 含む) ではウェアレベリングにより、上書きが物理的に同じセルへ
// 届く保証はない。確実な物理消去は原理的に保証できない。
func Shred(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	for range ShredPasses {
		if err := fillRandom(f, st.Size()); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return err
	}
	f.Sync()
	if err := f.Close(); err != nil {
		return err
	}

	b := make([]byte, 8)
	rand.Read(b)
	tmp := filepath.Join(filepath.Dir(path), "."+hex.EncodeToString(b))
	if err := os.Rename(path, tmp); err == nil {
		path = tmp
	}
	return os.Remove(path)
}
