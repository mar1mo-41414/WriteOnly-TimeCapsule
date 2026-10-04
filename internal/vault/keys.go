package vault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
)

// 鍵の欠片 (Shamir's Secret Sharing)
//
// age の X25519 秘密鍵 (32バイト) を k-of-n で分割する。欠片1個の中身:
//
//	version(1) | threshold k(1) | total n(1) | 番号 i(1) | 指紋(4) | 分割ID(4) | shamir 出力(33)
//
// を bech32 (HRP "wotc-share-") にして大文字で表記する。
// 指紋は公開鍵文字列の SHA-256 先頭4バイトで、別カプセルの欠片の混入検出と
// 復元結果の検証に使う。分割IDは分割1回ごとの乱数。同じ鍵でも分割し直すと
// 以前の欠片とは組み合わせられないため、その混入を見分けるのに使う。

const (
	shareHRP     = "wotc-share-"
	shareVersion = 1
	fpSize       = 4
	setIDSize    = 4
	shareHead    = 4 + fpSize + setIDSize
	secretHRP    = "age-secret-key-"
)

// Share は鍵の欠片1個。
type Share struct {
	Threshold, Total, Index int
	Fingerprint             [fpSize]byte
	SetID                   [setIDSize]byte
	Data                    []byte
}

func fingerprint(recipient string) (fp [fpSize]byte) {
	h := sha256.Sum256([]byte(recipient))
	copy(fp[:], h[:])
	return fp
}

func (s *Share) String() string {
	b := []byte{shareVersion, byte(s.Threshold), byte(s.Total), byte(s.Index)}
	b = append(b, s.Fingerprint[:]...)
	b = append(b, s.SetID[:]...)
	b = append(b, s.Data...)
	str, err := bech32Encode(shareHRP, b)
	if err != nil {
		panic(err)
	}
	return strings.ToUpper(str)
}

// ParseShare は "WOTC-SHARE-1..." 形式の文字列を読む。
func ParseShare(str string) (*Share, error) {
	hrp, b, err := bech32Decode(strings.TrimSpace(str))
	if err != nil {
		return nil, err
	}
	if hrp != shareHRP || len(b) < shareHead+2 || b[0] != shareVersion {
		return nil, errors.New("鍵の欠片の形式が不正です")
	}
	s := &Share{Threshold: int(b[1]), Total: int(b[2]), Index: int(b[3]), Data: b[shareHead:]}
	copy(s.Fingerprint[:], b[4:4+fpSize])
	copy(s.SetID[:], b[4+fpSize:shareHead])
	if s.Threshold < 2 || s.Threshold > s.Total || s.Index < 1 || s.Index > s.Total {
		return nil, errors.New("鍵の欠片の形式が不正です")
	}
	return s, nil
}

// identityBytes は age 秘密鍵の生の 32 バイトを取り出す。
func identityBytes(id *age.X25519Identity) ([]byte, error) {
	hrp, b, err := bech32Decode(id.String())
	if err != nil || hrp != secretHRP || len(b) != 32 {
		return nil, errors.New("秘密鍵の形式が想定外です")
	}
	return b, nil
}

func identityFromBytes(b []byte) (*age.X25519Identity, error) {
	s, err := bech32Encode(secretHRP, b)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.ToUpper(s))
}

// SplitIdentity は秘密鍵を total 個の欠片に分割する。threshold 個集めれば復元できる。
func SplitIdentity(id *age.X25519Identity, threshold, total int) ([]*Share, error) {
	if threshold < 2 || threshold > total || total > 255 {
		return nil, fmt.Errorf("分割数の指定が不正です (2 ≦ 必要数 ≦ 分割数 ≦ 255): %d-of-%d", threshold, total)
	}
	secret, err := identityBytes(id)
	if err != nil {
		return nil, err
	}
	parts, err := shamir.Split(secret, total, threshold)
	if err != nil {
		return nil, err
	}
	fp := fingerprint(id.Recipient().String())
	var set [setIDSize]byte
	if _, err := rand.Read(set[:]); err != nil {
		return nil, err
	}
	shares := make([]*Share, total)
	for i, p := range parts {
		shares[i] = &Share{Threshold: threshold, Total: total, Index: i + 1, Fingerprint: fp, SetID: set, Data: p}
	}
	// 念のため、先頭 k 個と末尾 k 個で復元できることを確かめてから返す。
	for _, sub := range [][]*Share{shares[:threshold], shares[total-threshold:]} {
		got, err := CombineShares(sub)
		if err != nil || got.String() != id.String() {
			return nil, errors.New("分割結果の検証に失敗しました")
		}
	}
	return shares, nil
}

// CombineShares は欠片から秘密鍵を復元する。
func CombineShares(shares []*Share) (*age.X25519Identity, error) {
	if len(shares) == 0 {
		return nil, errors.New("鍵の欠片がありません")
	}
	first := shares[0]
	seen := map[int]bool{}
	var parts [][]byte
	for _, s := range shares {
		if s.Fingerprint != first.Fingerprint {
			return nil, errors.New("別のカプセルの鍵の欠片が混ざっています")
		}
		if s.SetID != first.SetID || s.Threshold != first.Threshold || s.Total != first.Total {
			return nil, errors.New("別の回に分割した鍵の欠片が混ざっています (同じカプセルでも、分割し直すと以前の欠片とは組み合わせられません)")
		}
		if seen[s.Index] {
			continue // 同じ欠片が重複して渡されただけなら無視する
		}
		seen[s.Index] = true
		parts = append(parts, s.Data)
	}
	if len(parts) < first.Threshold {
		return nil, fmt.Errorf("鍵の欠片が足りません (%d 個必要、%d 個あります)", first.Threshold, len(parts))
	}
	secret, err := shamir.Combine(parts)
	if err != nil {
		return nil, err
	}
	id, err := identityFromBytes(secret)
	if err != nil {
		return nil, err
	}
	if fingerprint(id.Recipient().String()) != first.Fingerprint {
		return nil, errors.New("鍵の復元に失敗しました (欠片が壊れている可能性があります)")
	}
	return id, nil
}

// DefaultKeyName は --key-out にフォルダだけが指定されたときに使うファイル名。
const DefaultKeyName = "vault-secret.key"

// ResolveOut は出力先にフォルダが指定された場合 ("keys/" や既存のフォルダ)、
// その中の defaultName を指すパスにする。ファイル名が指定されていればそのまま返す。
func ResolveOut(p, defaultName string) string {
	if p == "" {
		return defaultName
	}
	if strings.HasSuffix(p, "/") || strings.HasSuffix(p, string(filepath.Separator)) {
		return filepath.Join(p, defaultName)
	}
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return filepath.Join(p, defaultName)
	}
	return p
}

// ShareFileName は分割時の欠片ファイル名を返す (例: vault-secret.share1-of-3.key)。
func ShareFileName(keyOut string, s *Share) string {
	keyOut = ResolveOut(keyOut, DefaultKeyName)
	dir, name := filepath.Split(keyOut)
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	if stem == "" || stem == "." { // ".key" のように名前部分が無い場合
		stem = strings.TrimSuffix(DefaultKeyName, filepath.Ext(DefaultKeyName))
	}
	return filepath.Join(dir, fmt.Sprintf("%s.share%d-of-%d.key", stem, s.Index, s.Total))
}

// MaxKeyFileSize は鍵ファイルとして読み込む最大サイズ。秘密鍵・欠片・タイムロック鍵はどれも 1KB 前後なので、
// これより大きいものはコンテナなど別のファイルの取り違えとみなす (巨大なファイルを丸ごと読み込まない)。
const MaxKeyFileSize = 64 << 10

// readKeyFile は鍵・公開鍵などの小さなテキストファイルを読む。フォルダや巨大なファイルは分かりやすく拒否する。
func readKeyFile(p, hint string) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s はフォルダです (%s。欠片がフォルダに入っているなら、中のファイルを --key で1つずつ指定します)", p, hint)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s は通常のファイルではありません (%s)", p, hint)
	}
	if st.Size() > MaxKeyFileSize {
		return nil, fmt.Errorf("%s は鍵ファイルではありません (%d バイトもあり大きすぎます。コンテナなど別のファイルを指定していませんか? %s)", p, st.Size(), hint)
	}
	return os.ReadFile(p)
}

// writeKeyFile は鍵ファイルを O_EXCL・0600 で作る (親ディレクトリは自動作成)。
func writeKeyFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(content)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// WriteKeys は秘密鍵を keyOut に書き出す。threshold > 0 なら分割して欠片ファイル群を書き、
// 完全な秘密鍵はディスクに一切書かない。作成したファイルの一覧を返す。
func WriteKeys(id *age.X25519Identity, keyOut string, threshold, total int) ([]string, error) {
	recipient := id.Recipient().String()
	now := time.Now().Format(time.RFC3339)
	keyOut = ResolveOut(keyOut, DefaultKeyName)
	if threshold == 0 {
		content := fmt.Sprintf("# WriteOnly-TimeCapsule secret key\n# created: %s\n# public key: %s\n%s\n", now, recipient, id.String())
		return []string{keyOut}, writeKeyFile(keyOut, content)
	}

	shares, err := SplitIdentity(id, threshold, total)
	if err != nil {
		return nil, err
	}
	var written []string
	for _, s := range shares {
		p := ShareFileName(keyOut, s)
		content := fmt.Sprintf("# WriteOnly-TimeCapsule 鍵の欠片 %d/%d (%d 個集めると開封できます)\n# created: %s\n# public key: %s\n%s\n",
			s.Index, s.Total, s.Threshold, now, recipient, s)
		if err := writeKeyFile(p, content); err != nil {
			for _, w := range written {
				os.Remove(w)
			}
			return nil, err
		}
		written = append(written, p)
	}
	return written, nil
}

// LoadKeys は鍵ファイル群を読み、秘密鍵を得る。優先順:
//  1. 完全な秘密鍵 (AGE-SECRET-KEY-1...)
//  2. タイムロック鍵 (開封可能日時を過ぎていれば drand から署名を取って復元)
//  3. 鍵の欠片 (WOTC-SHARE-1...) を集めて復元 (= タイムロックの非常口)
//
// 1ファイルに複数の欠片が書かれていてもよい。
func LoadKeys(paths []string) (*age.X25519Identity, error) {
	var shares []*Share
	var timelocks [][]byte
	for _, p := range paths {
		b, err := readKeyFile(p, "--key には秘密鍵・鍵の欠片・タイムロック鍵のファイルを指定してください")
		if err != nil {
			return nil, err
		}
		if IsTimelockFile(b) {
			timelocks = append(timelocks, b)
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			upper := strings.ToUpper(line)
			switch {
			case line == "" || strings.HasPrefix(line, "#"):
			case strings.HasPrefix(upper, "AGE-SECRET-KEY-1"):
				id, err := age.ParseX25519Identity(line)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: 秘密鍵が壊れています (書き写し間違い?): %w", p, n, err)
				}
				return id, nil
			case strings.HasPrefix(upper, "WOTC-SHARE-1"):
				s, err := ParseShare(line)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: %w", p, n, err)
				}
				shares = append(shares, s)
			case strings.HasPrefix(strings.ToLower(line), "age1"):
				return nil, fmt.Errorf("%s は公開鍵です (--key には秘密鍵・鍵の欠片・タイムロック鍵を指定してください)", p)
			default:
				return nil, fmt.Errorf("%s:%d: 秘密鍵でも鍵の欠片でもない行があります (コンテナや別のファイルを --key に指定していませんか?)", p, n)
			}
		}
	}

	var tlErr error
	for _, b := range timelocks {
		id, err := UnlockTimelock(b)
		if err == nil {
			return id, nil
		}
		tlErr = err
	}
	if len(shares) == 0 {
		if tlErr != nil {
			return nil, tlErr
		}
		return nil, errors.New("秘密鍵も鍵の欠片も見つかりません")
	}
	slices.SortFunc(shares, func(a, b *Share) int { return a.Index - b.Index })
	id, err := CombineShares(shares)
	if err != nil && tlErr != nil {
		return nil, fmt.Errorf("%w (非常口の欠片も使えません: %w)", tlErr, err)
	}
	return id, err
}
