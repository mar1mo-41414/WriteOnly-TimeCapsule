package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ShredPasses は Shred が乱数で上書きする回数。
const ShredPasses = 3

// CheckRemovable は path を Shred できるか (上書きと削除の両方ができるか) を、何も変更せずに確かめる。
// 破棄は「1つでもできないものがあれば何も触らない」ようにするため、実行前にこれで全対象を確認する。
func CheckRemovable(path string) error {
	lst, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s が見つかりません", path)
		}
		return err
	}
	target := path
	if lst.Mode()&os.ModeSymlink != 0 {
		// シンボリックリンクなら、リンク自体を消すためにリンクのあるフォルダにも書ける必要がある
		if dir := filepath.Dir(path); !canWrite(dir) {
			return fmt.Errorf("%s を消去できません: フォルダ %s に書き込み権限がありません", path, dir)
		}
		if target, err = filepath.EvalSymlinks(path); err != nil {
			return fmt.Errorf("%s はリンク切れのシンボリックリンクです", path)
		}
	}
	st, err := os.Stat(target)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s は通常のファイルではないため消去できません", path)
	}
	if !canWrite(target) {
		return fmt.Errorf("%s を消去できません: 書き込み禁止になっています (意図的でなければ chmod u+w で許可してから再実行してください)", target)
	}
	if dir := filepath.Dir(target); !canWrite(dir) {
		return fmt.Errorf("%s を消去できません: フォルダ %s に書き込み権限がありません", target, dir)
	}
	return nil
}

// Shred はファイルを乱数で複数回上書きし、ランダムな名前にリネームしてから削除する
// (GNU shred -u 相当。macOS には shred が無いため自前で実装している)。
// 先に CheckRemovable で確認し、削除まで完了できない場合は何も変更しない
// (「中身だけ消えて空のファイルが残る」状態を作らない)。
// シンボリックリンクを渡された場合は、リンク先の本体を消去したうえでリンクも消す。
//
// 注意: SSD (APFS 含む) ではウェアレベリングにより、上書きが物理的に同じセルへ
// 届く保証はない。確実な物理消去は原理的に保証できない。
func Shred(path string) error {
	if err := CheckRemovable(path); err != nil {
		return err
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if err := shredFile(target); err != nil {
		return err
	}
	if target != path {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return nil
}

// ShredAll は paths を順に Shred する。途中で失敗した場合は、既に破棄できた
// 対象の一覧とエラーを返す (破棄は原子的ではない: 呼び出し側は「何が消えて
// 何が残ったか」を利用者に明示すること)。
func ShredAll(paths []string) (destroyed []string, err error) {
	for _, p := range paths {
		if err := Shred(p); err != nil {
			return destroyed, fmt.Errorf("%s: %w", p, err)
		}
		destroyed = append(destroyed, p)
	}
	return destroyed, nil
}

// syncDir はディレクトリのメタデータ (ファイルの作成・削除・リネーム) を
// 永続化する。削除後にこれをしないと、クラッシュ時に消したはずのファイルが
// 復活する可能性を排除できない。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func shredFile(path string) error {
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
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("%s の上書きを保存できませんでした: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+hex.EncodeToString(b))
	if err := os.Rename(path, tmp); err == nil {
		path = tmp
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
