package vault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

const maxMetaSize = 1 << 20

// Meta はレコードごとに暗号化して保存するメタデータ。
type Meta struct {
	Name    string      `json:"name"`
	Size    int64       `json:"size"`
	ModTime time.Time   `json:"mtime"`
	Mode    os.FileMode `json:"mode"`
	MIME    string      `json:"mime,omitempty"`
	AddedAt time.Time   `json:"added_at"`
}

// InitOptions は Init の引数。Threshold が 0 なら鍵を分割しない。
type InitOptions struct {
	Container, PubKey, KeyOut string
	Size                      int64
	Threshold, Shares         int
	// Unlock が非ゼロなら、秘密鍵を TimelockOut へタイムロックしても書き出す。
	// 通常の鍵出力 (KeyOut の秘密鍵または欠片) はそのまま非常口として残る。
	Unlock      time.Time
	TimelockOut string
}

// Init は鍵ペアを生成し、固定サイズのコンテナと公開鍵ファイル・秘密鍵ファイル
// (分割時は欠片ファイル群) を作成する。作成した鍵ファイルの一覧を返す。
func Init(o InitOptions) (recipient string, keyFiles []string, err error) {
	if err := checkSize(o.Size); err != nil {
		return "", nil, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", nil, err
	}
	recipient = id.Recipient().String()

	// 既存ファイルの上書き防止のため、全部 O_EXCL で作る。
	// 大きなコンテナを確保する前に、失敗しやすい鍵ファイルの作成を済ませておく。
	keyFiles, err = WriteKeys(id, o.KeyOut, o.Threshold, o.Shares)
	if err != nil {
		return "", nil, err
	}
	created := slices.Clone(keyFiles)
	defer func() {
		if err != nil {
			for _, p := range created {
				os.Remove(p)
			}
		}
	}()
	if !o.Unlock.IsZero() {
		if err = WriteTimelock(o.TimelockOut, id, o.Unlock); err != nil {
			return "", nil, err
		}
		created = append(created, o.TimelockOut)
	}

	pub, err := os.OpenFile(o.PubKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", nil, err
	}
	created = append(created, o.PubKey)
	_, err = pub.WriteString(recipient + "\n")
	if cerr := pub.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", nil, err
	}

	f, err := os.OpenFile(o.Container, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, err
	}
	created = append(created, o.Container)
	defer f.Close()
	if err = fillRandom(f, o.Size); err != nil {
		return "", nil, err
	}
	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return "", nil, err
	}
	k, err := deriveKeys(recipient, salt)
	if err != nil {
		return "", nil, err
	}
	err = writeSuperblock(f, &superblock{salt: salt, keys: k, used: 0})
	return recipient, keyFiles, err
}

// LoadRecipient は公開鍵ファイルを読む。
func LoadRecipient(pubPath string) (*age.X25519Recipient, error) {
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return age.ParseX25519Recipient(line)
	}
	return nil, fmt.Errorf("%s に公開鍵がありません", pubPath)
}

// LoadIdentity は秘密鍵ファイル (または欠片を必要数含むファイル) 1個を読む。
func LoadIdentity(path string) (*age.X25519Identity, error) {
	return LoadKeys([]string{path})
}

// Verify はコンテナが公開鍵と対応しているかだけを確認する。中身に関する情報は返さない。
func Verify(containerPath string, r *age.X25519Recipient) error {
	f, err := os.Open(containerPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = readSuperblock(f, r.String())
	return err
}

// Add は srcPath のファイルを暗号化してコンテナに追記する。
// コンテナのサイズ・更新日時は変化させない。
func Add(containerPath string, r *age.X25519Recipient, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s: 通常ファイルのみ追加できます", srcPath)
	}

	f, err := os.OpenFile(containerPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	cst, err := f.Stat()
	if err != nil {
		return err
	}
	// 追記しても見た目の更新日時が変わらないよう、最後に元へ戻す。
	defer os.Chtimes(containerPath, cst.ModTime(), cst.ModTime())

	sb, err := readSuperblock(f, r.String())
	if err != nil {
		return err
	}
	pos := superblockSize + sb.used
	end := cst.Size()
	if pos+lenPrefixSize > end {
		return ErrNoSpace
	}

	// 本体を先に書き、長さプレフィックスとスーパーブロックは最後に更新する。
	// 途中で失敗しても used は進まないので、既存レコードは壊れない。
	mw, err := newMaskedWriter(f, &sb.keys, pos+lenPrefixSize, end)
	if err != nil {
		return err
	}
	aw, err := age.Encrypt(mw, r)
	if err != nil {
		return err
	}
	head := make([]byte, 512)
	n, _ := io.ReadFull(src, head)
	head = head[:n]
	meta := Meta{
		Name:    filepath.Base(srcPath),
		Size:    st.Size(),
		ModTime: st.ModTime(),
		Mode:    st.Mode().Perm(),
		MIME:    detectMIME(srcPath, head),
		AddedAt: time.Now(),
	}
	mj, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(mj)))
	body := io.MultiReader(bytes.NewReader(lb[:]), bytes.NewReader(mj), bytes.NewReader(head), src)
	if _, err := io.Copy(aw, body); err != nil {
		return err
	}
	if err := aw.Close(); err != nil {
		return err
	}

	pw, err := newMaskedWriter(f, &sb.keys, pos, pos+lenPrefixSize)
	if err != nil {
		return err
	}
	var plen [lenPrefixSize]byte
	binary.BigEndian.PutUint64(plen[:], uint64(mw.n))
	if _, err := pw.Write(plen[:]); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	sb.used += lenPrefixSize + mw.n
	return writeSuperblock(f, sb)
}

func detectMIME(name string, head []byte) string {
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return http.DetectContentType(head)
}

// Opened は開封で展開された1ファイルの情報。
type Opened struct {
	Meta Meta
	Path string
}

// Open は秘密鍵でコンテナ全体を復号し、outDir に全ファイルを展開する。
// コンテナ自体は変更しない。
func Open(containerPath string, id *age.X25519Identity, outDir string) ([]Opened, error) {
	f, err := os.Open(containerPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sb, err := readSuperblock(f, id.Recipient().String())
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}

	var out []Opened
	pos, end := int64(superblockSize), superblockSize+sb.used
	for pos < end {
		if pos+lenPrefixSize > end {
			return out, ErrMismatch
		}
		lr, err := newMaskedReader(f, &sb.keys, pos, pos+lenPrefixSize)
		if err != nil {
			return out, err
		}
		var plen [lenPrefixSize]byte
		if _, err := io.ReadFull(lr, plen[:]); err != nil {
			return out, err
		}
		n := int64(binary.BigEndian.Uint64(plen[:]))
		start := pos + lenPrefixSize
		if n <= 0 || n > end-start {
			return out, ErrMismatch
		}
		o, err := openRecord(f, sb, id, start, start+n, outDir)
		if err != nil {
			return out, fmt.Errorf("レコード %d の復号に失敗: %w", len(out)+1, err)
		}
		out = append(out, o)
		pos = start + n
	}
	return out, nil
}

func openRecord(f *os.File, sb *superblock, id *age.X25519Identity, start, end int64, outDir string) (Opened, error) {
	mr, err := newMaskedReader(f, &sb.keys, start, end)
	if err != nil {
		return Opened{}, err
	}
	dr, err := age.Decrypt(mr, id)
	if err != nil {
		return Opened{}, err
	}
	br := bufio.NewReader(dr)
	var lb [4]byte
	if _, err := io.ReadFull(br, lb[:]); err != nil {
		return Opened{}, err
	}
	ml := binary.BigEndian.Uint32(lb[:])
	if ml > maxMetaSize {
		return Opened{}, ErrMismatch
	}
	mj := make([]byte, ml)
	if _, err := io.ReadFull(br, mj); err != nil {
		return Opened{}, err
	}
	var meta Meta
	if err := json.Unmarshal(mj, &meta); err != nil {
		return Opened{}, err
	}

	dst, path, err := createUnique(outDir, safeName(meta.Name), meta.Mode.Perm()|0o600)
	if err != nil {
		return Opened{}, err
	}
	if _, err := io.Copy(dst, br); err != nil {
		dst.Close()
		os.Remove(path)
		return Opened{}, err
	}
	if err := dst.Close(); err != nil {
		return Opened{}, err
	}
	if !meta.ModTime.IsZero() {
		os.Chtimes(path, meta.ModTime, meta.ModTime)
	}
	return Opened{Meta: meta, Path: path}, nil
}

// safeName はメタデータ中のファイル名からディレクトリ成分を取り除く (パストラバーサル対策)。
func safeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == ".." || name == "/" || name == "" {
		return "file"
	}
	return name
}

func createUnique(dir, name string, perm os.FileMode) (*os.File, string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; ; i++ {
		cand := name
		if i > 0 {
			cand = stem + " (" + strconv.Itoa(i) + ")" + ext
		}
		p := filepath.Join(dir, cand)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			return f, p, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
}
