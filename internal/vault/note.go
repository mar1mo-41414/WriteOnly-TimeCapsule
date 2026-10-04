package vault

// コメント (メモ)
//
// 「何のためのカプセルか」のような短いメモを、コンテナ自身の中に平文で埋め込む。
// コンテナだけを別の場所へ移してもメモが一緒に付いていくよう、別ファイルにはしない。
// 置き場所はスーパーブロック (先頭512バイト) のうち、使われていない乱数パディング部分:
//
//	[72, 512)  "WOTCNOTE"(8) | version(1) | 長さ(2) | CRC32(4) | 本文 (UTF-8) | 乱数
//
// メモは暗号化しない (誰でも読める) し、鍵も要らない。追加したファイルの中身や量とは無関係。
// コメントの無いコンテナ (以前のバージョンで作ったものを含む) では、この領域はただの乱数なので
// 目印と CRC が偶然一致することは事実上なく、「コメントなし」として扱われる。

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// noteOffset はスーパーブロック中で暗号化された管理情報が終わる位置 (= メモ領域の先頭)。
	noteOffset  = saltSize + chacha20poly1305.NonceSizeX + stateSize + chacha20poly1305.Overhead
	noteMagic   = "WOTCNOTE"
	noteVersion = 1
	noteHeader  = len(noteMagic) + 1 + 2 + 4
	// MaxCommentBytes はコメントの最大バイト数 (UTF-8)。日本語ならおよそ140文字。
	MaxCommentBytes = superblockSize - noteOffset - noteHeader
)

// NormalizeComment はコメントの前後の空白を除き、長さと使える文字を確認する。
func NormalizeComment(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", errors.New("コメントに不正な文字コードが含まれています (UTF-8 で書いてください)")
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return "", errors.New("コメントに制御文字は使えません")
		}
	}
	if len(s) > MaxCommentBytes {
		return "", fmt.Errorf("コメントが長すぎます (%d バイト。最大 %d バイト、日本語ならおよそ %d 文字まで)", len(s), MaxCommentBytes, MaxCommentBytes/3)
	}
	return s, nil
}

// writeComment はコンテナのメモ領域にコメントを書く。
func writeComment(f *os.File, comment string) error {
	b := make([]byte, noteHeader, noteHeader+len(comment))
	copy(b, noteMagic)
	b[len(noteMagic)] = noteVersion
	binary.BigEndian.PutUint16(b[len(noteMagic)+1:], uint16(len(comment)))
	binary.BigEndian.PutUint32(b[len(noteMagic)+3:], crc32.ChecksumIEEE([]byte(comment)))
	b = append(b, comment...)
	if _, err := f.WriteAt(b, noteOffset); err != nil {
		return err
	}
	return f.Sync()
}

// ReadComment はコンテナに埋め込まれたコメントを読む。鍵は不要。
// コメントが無ければ ok=false を返す。
func ReadComment(containerPath string) (comment string, ok bool, err error) {
	f, err := os.Open(containerPath)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	buf := make([]byte, superblockSize-noteOffset)
	if _, err := f.ReadAt(buf, noteOffset); err != nil {
		return "", false, nil // 小さすぎるファイルなどはコメントなし扱い
	}
	if !bytes.HasPrefix(buf, []byte(noteMagic)) || buf[len(noteMagic)] != noteVersion {
		return "", false, nil
	}
	n := int(binary.BigEndian.Uint16(buf[len(noteMagic)+1:]))
	sum := binary.BigEndian.Uint32(buf[len(noteMagic)+3:])
	if n > MaxCommentBytes {
		return "", false, errors.New("コメント領域が壊れています")
	}
	text := buf[noteHeader : noteHeader+n]
	if crc32.ChecksumIEEE(text) != sum {
		return "", false, errors.New("コメント領域が壊れています")
	}
	return string(text), true, nil
}
