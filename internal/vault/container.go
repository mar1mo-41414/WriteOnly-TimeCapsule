// Package vault は書き込み専用タイムカプセルのコンテナ形式を実装する。
//
// コンテナ全体のレイアウト:
//
//	[0, 512)      スーパーブロック
//	              salt(16) | nonce(24) | seal(state 16B + tag 16B) | 乱数パディング
//	[512, size)   データ領域。レコードを先頭から詰めて書く。未使用部分は乱数。
//
// レコード (データ領域内、マスク前の平文表現):
//
//	len(8, big endian) | age 暗号文 (len バイト)
//
// データ領域は公開鍵とsaltから導出した鍵の XChaCha20 キーストリームで
// 位置ごとにマスクしている。これにより age のテキストヘッダ
// ("age-encryption.org/v1" など) がコンテナ上に現れず、レコード境界も
// 乱数で埋めた空き領域と区別できない。
package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	superblockSize = 512
	saltSize       = 16
	stateSize      = 16
	lenPrefixSize  = 8

	// MinSize はコンテナの最小サイズ。
	MinSize = 64 * 1024
	// MaxSize は XChaCha20 のブロックカウンタ(32bit)で扱える上限未満に抑える。
	MaxSize = 128 << 30

	stateMagic   = "WOTC"
	stateVersion = 1
)

var (
	// ErrNoSpace は追記先の容量が足りないときに返す。残量などの情報は含めない。
	ErrNoSpace = errors.New("容量不足")
	// ErrMismatch はコンテナが壊れているか、鍵が一致しないときに返す。
	ErrMismatch = errors.New("コンテナが壊れているか、鍵が一致しません")
)

type keys struct {
	mask  [32]byte
	state [32]byte
}

func deriveKeys(recipient string, salt []byte) (keys, error) {
	var k keys
	for _, x := range []struct {
		dst  *[32]byte
		info string
	}{{&k.mask, "wotc v1 data mask"}, {&k.state, "wotc v1 state seal"}} {
		r := hkdf.New(sha256.New, []byte(recipient), salt, []byte(x.info))
		if _, err := io.ReadFull(r, x.dst[:]); err != nil {
			return k, err
		}
	}
	return k, nil
}

// superblock はコンテナ先頭に置く書き込み位置管理情報 (復号済みの状態)。
type superblock struct {
	salt []byte
	keys keys
	used int64 // データ領域の使用バイト数
}

// backupSize はスーパーブロックのバックアップ (B面) の大きさ。
// B面は A面 (先頭 [0,72)) と同じ構造の独立した複写で、コンテナ末尾
// [size-72, size) に置く。コメント領域 ([72,512)) とは重ならず、
// コンテナ単体で持ち運ぶ設計も壊さない。A面は従来の v1 形式のままなので、
// B面を知らない旧バージョンでも A面から開ける (旧バージョンの Add は
// B面を更新しないが、読み取りは常に A面優先なので誤復旧はしない)。
const backupSize = noteOffset

// errBackupNoSpace はデータ領域が末尾まで埋まっていて B面を置けないときに返す。
var errBackupNoSpace = errors.New("データ領域に空きがなく、スーパーブロックのバックアップを置けません")

// sealSuperblock はスーパーブロックの封印済みブロック (72バイト) を作る。
// 呼ぶたびに nonce は乱数で新しくする (A面・B面は独立した封印になる)。
func sealSuperblock(sb *superblock) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sb.keys.state[:])
	if err != nil {
		return nil, err
	}
	buf := make([]byte, noteOffset)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	copy(buf, sb.salt)
	nonce := buf[saltSize : saltSize+chacha20poly1305.NonceSizeX]
	plain := make([]byte, stateSize)
	copy(plain, stateMagic)
	binary.BigEndian.PutUint32(plain[4:], stateVersion)
	binary.BigEndian.PutUint64(plain[8:], uint64(sb.used))
	sealed := aead.Seal(nil, nonce, plain, sb.salt)
	copy(buf[saltSize+len(nonce):], sealed)
	return buf, nil
}

func writeSuperblock(f *os.File, sb *superblock) error {
	buf, err := sealSuperblock(sb)
	if err != nil {
		return err
	}
	// 書き換えるのは管理情報の部分だけ。その後ろ (コメント領域・乱数) は init 時のまま残す。
	if _, err := f.WriteAt(buf, 0); err != nil {
		return err
	}
	return f.Sync()
}

// backupOffset は B面の置き場所 (ファイル末尾) を返す。
func backupOffset(f *os.File) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	off := st.Size() - backupSize
	if off < superblockSize {
		return 0, errBackupNoSpace
	}
	return off, nil
}

// writeSuperblockBackup は B面をコンテナ末尾に書く。
// データ領域の末尾72バイト以内にレコードがある場合は、そのレコードを
// 壊さないよう書かずに errBackupNoSpace を返す。
func writeSuperblockBackup(f *os.File, sb *superblock) error {
	off, err := backupOffset(f)
	if err != nil {
		return err
	}
	if superblockSize+sb.used > off {
		return errBackupNoSpace
	}
	buf, err := sealSuperblock(sb)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(buf, off); err != nil {
		return err
	}
	return f.Sync()
}

// readSuperblock は A面を読み、読めない場合に限り B面 (末尾のバックアップ)
// を試す。B面から読めた場合は復旧として扱い、その旨を表示する。
// A面が正常なら B面は (古くても) 一切使わない。
func readSuperblock(f *os.File, recipient string) (*superblock, error) {
	sb, err := readSuperblockAt(f, recipient, 0)
	if err == nil {
		return sb, nil
	}
	if sbB, berr := readBackupSuperblock(f, recipient); berr == nil {
		fmt.Fprintln(os.Stderr, "警告: 主スーパーブロックが読めないため、コンテナ末尾のバックアップから復旧しました (バックアップ時点の状態で開きます。直前の追記が反映されていない可能性があります)")
		return sbB, nil
	}
	return nil, err
}

// readBackupSuperblock は B面だけを読む (復旧表示はしない)。
func readBackupSuperblock(f *os.File, recipient string) (*superblock, error) {
	off, err := backupOffset(f)
	if err != nil {
		return nil, err
	}
	return readSuperblockAt(f, recipient, off)
}

func readSuperblockAt(f *os.File, recipient string, off int64) (*superblock, error) {
	buf := make([]byte, noteOffset)
	if _, err := f.ReadAt(buf, off); err != nil {
		return nil, ErrMismatch
	}
	salt := append([]byte(nil), buf[:saltSize]...)
	k, err := deriveKeys(recipient, salt)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k.state[:])
	if err != nil {
		return nil, err
	}
	nonce := buf[saltSize : saltSize+chacha20poly1305.NonceSizeX]
	sealed := buf[saltSize+len(nonce) : saltSize+len(nonce)+stateSize+aead.Overhead()]
	plain, err := aead.Open(nil, nonce, sealed, salt)
	if err != nil || string(plain[:4]) != stateMagic || binary.BigEndian.Uint32(plain[4:]) != stateVersion {
		return nil, ErrMismatch
	}
	used := int64(binary.BigEndian.Uint64(plain[8:]))
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if used < 0 || superblockSize+used > st.Size() {
		return nil, ErrMismatch
	}
	return &superblock{salt: salt, keys: k, used: used}, nil
}

// streamAt はデータ領域の絶対位置 pos から始まるマスク用キーストリームを返す。
func streamAt(k *keys, pos int64) (*chacha20.Cipher, error) {
	c, err := chacha20.NewUnauthenticatedCipher(k.mask[:], make([]byte, chacha20.NonceSizeX))
	if err != nil {
		return nil, err
	}
	c.SetCounter(uint32(pos / 64))
	if skip := pos % 64; skip > 0 {
		scratch := make([]byte, skip)
		c.XORKeyStream(scratch, scratch)
	}
	return c, nil
}

// maskedWriter はコンテナの pos から end までの範囲にマスクしながら書き込む。
type maskedWriter struct {
	f        *os.File
	pos, end int64
	c        *chacha20.Cipher
	n        int64
}

func newMaskedWriter(f *os.File, k *keys, pos, end int64) (*maskedWriter, error) {
	c, err := streamAt(k, pos)
	if err != nil {
		return nil, err
	}
	return &maskedWriter{f: f, pos: pos, end: end, c: c}, nil
}

func (w *maskedWriter) Write(p []byte) (int, error) {
	if w.pos+int64(len(p)) > w.end {
		return 0, ErrNoSpace
	}
	buf := make([]byte, len(p))
	w.c.XORKeyStream(buf, p)
	if _, err := w.f.WriteAt(buf, w.pos); err != nil {
		return 0, err
	}
	w.pos += int64(len(p))
	w.n += int64(len(p))
	return len(p), nil
}

// maskedReader はコンテナの [pos, end) をマスク解除しながら読む。
type maskedReader struct {
	r *io.SectionReader
	c *chacha20.Cipher
}

func newMaskedReader(f *os.File, k *keys, pos, end int64) (*maskedReader, error) {
	c, err := streamAt(k, pos)
	if err != nil {
		return nil, err
	}
	return &maskedReader{r: io.NewSectionReader(f, pos, end-pos), c: c}, nil
}

func (r *maskedReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.c.XORKeyStream(p[:n], p[:n])
	return n, err
}

// fillRandom は f の [0, size) を暗号論的乱数で実データとして埋める (sparse にしない)。
// crypto/rand を大量に読む代わりに、乱数鍵の ChaCha20 キーストリームを使う。
func fillRandom(f *os.File, size int64) error {
	key := make([]byte, chacha20.KeySize)
	nonce := make([]byte, chacha20.NonceSize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	for off := int64(0); off < size; off += chunk {
		n := min(int64(chunk), size-off)
		b := buf[:n]
		clear(b)
		c.XORKeyStream(b, b)
		if _, err := f.WriteAt(b, off); err != nil {
			return err
		}
	}
	return f.Sync()
}

func checkSize(size int64) error {
	if size < MinSize {
		return fmt.Errorf("サイズが小さすぎます (最小 %d バイト)", MinSize)
	}
	if size > MaxSize {
		return fmt.Errorf("サイズが大きすぎます (最大 %d バイト)", int64(MaxSize))
	}
	return nil
}
