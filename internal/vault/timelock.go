package vault

// タイムロック (drand / tlock)
//
// 秘密鍵そのものを tlock で「drand quicknet の指定ラウンド」に向けて暗号化する。
// 復号に必要なのはそのラウンドの BLS 署名で、drand ネットワークがその時刻に
// なって初めて生成・公開する。つまり開封可能日時より前には、復号鍵が
// 世界のどこにも存在しない (時計をいじっても、コードを改造しても開かない)。
//
// ネットワークのパラメータ (公開鍵・genesis・周期) は埋め込んであるので、
// ロックする側はオフラインで動く。ネットワークが必要なのは開封時だけ。

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	"github.com/drand/tlock"
)

// drand quicknet (League of Entropy)。値は /info エンドポイントの内容そのまま。
const (
	quicknetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
	quicknetPublicKey = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
	quicknetScheme    = "bls-unchained-g1-rfc9380"
	quicknetGenesis   = 1692803367
	quicknetPeriod    = 3
)

// DrandHosts は開封時に署名を取りに行く drand の HTTP ミラー (上から順に試す)。
var DrandHosts = []string{
	"https://api.drand.sh",
	"https://api2.drand.sh",
	"https://api3.drand.sh",
	"https://drand.cloudflare.com",
}

var (
	// ErrTooEarly は開封可能日時より前に開けようとしたときに返す。
	ErrTooEarly = errors.New("まだ開封できません")
	// ErrDrandUnreachable は drand に接続できないときに返す。
	ErrDrandUnreachable = errors.New("drand ネットワークに接続できません")
)

const tlockHeader = "# WriteOnly-TimeCapsule タイムロック鍵"

// RoundTime はラウンドが公開される時刻を返す。
func RoundTime(round uint64) time.Time {
	return time.Unix(quicknetGenesis+int64(round-1)*quicknetPeriod, 0)
}

// RoundAt は時刻 t 以降に公開される最初のラウンドを返す (t より前には絶対に公開されない)。
func RoundAt(t time.Time) uint64 {
	d := t.Unix() - quicknetGenesis
	if d <= 0 {
		return 1
	}
	return uint64((d+quicknetPeriod-1)/quicknetPeriod) + 1
}

// quicknet は tlock.Network の実装。署名取得は複数ミラーへフォールバックする。
type quicknet struct {
	scheme  crypto.Scheme
	pub     kyber.Point
	hosts   []string
	client  *http.Client
	lastErr error
}

func newQuicknet() (*quicknet, error) {
	sch, err := crypto.SchemeFromName(quicknetScheme)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(quicknetPublicKey)
	if err != nil {
		return nil, err
	}
	pub := sch.KeyGroup.Point()
	if err := pub.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return &quicknet{scheme: *sch, pub: pub, hosts: DrandHosts, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (n *quicknet) ChainHash() string      { return quicknetChainHash }
func (n *quicknet) PublicKey() kyber.Point { return n.pub }
func (n *quicknet) Scheme() crypto.Scheme  { return n.scheme }
func (n *quicknet) SwitchChainHash(string) error {
	return errors.New("quicknet 以外のチェーンには対応していません")
}
func (n *quicknet) Current(t time.Time) uint64 {
	return uint64((t.Unix()-quicknetGenesis)/quicknetPeriod) + 1
}

// Signature は指定ラウンドの署名を drand から取得する。
// tlock はここでのエラーを全部「早すぎる」と扱うので、本当の理由を lastErr に残す。
func (n *quicknet) Signature(round uint64) ([]byte, error) {
	n.lastErr = nil
	var errs []error
	for _, h := range n.hosts {
		sig, status, err := n.fetch(h, round)
		if err == nil {
			return sig, nil
		}
		// 未来のラウンドはミラーが 404/425 などを返す
		if status >= 400 && status < 500 {
			n.lastErr = ErrTooEarly
			return nil, n.lastErr
		}
		errs = append(errs, err)
	}
	// 全ミラーの生エラーを並べると読みにくいので、代表として最初の1件だけ添える。
	n.lastErr = fmt.Errorf("%w (ミラー %d か所すべて失敗。インターネット接続を確認してください。例: %v)", ErrDrandUnreachable, len(n.hosts), errs[0])
	return nil, n.lastErr
}

func (n *quicknet) fetch(host string, round uint64) ([]byte, int, error) {
	url := fmt.Sprintf("%s/%s/public/%d", host, quicknetChainHash, round)
	resp, err := n.client.Get(url)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = fmt.Errorf("%s: %w", host, ue.Err)
		}
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("%s: HTTP %d", host, resp.StatusCode)
	}
	var v struct {
		Round     uint64 `json:"round"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&v); err != nil {
		return nil, resp.StatusCode, err
	}
	if v.Round != round {
		return nil, resp.StatusCode, fmt.Errorf("別のラウンド (%d) が返ってきました", v.Round)
	}
	sig, err := hex.DecodeString(v.Signature)
	return sig, resp.StatusCode, err
}

// TimelockIdentity は秘密鍵を unlock 以降にしか復号できない形に暗号化し、ファイル内容を返す。
func TimelockIdentity(id *age.X25519Identity, unlock time.Time) ([]byte, error) {
	n, err := newQuicknet()
	if err != nil {
		return nil, err
	}
	round := RoundAt(unlock)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\n", tlockHeader)
	fmt.Fprintf(&buf, "# 開封可能日時: %s\n", RoundTime(round).Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&buf, "# public key: %s\n", id.Recipient().String())
	fmt.Fprintf(&buf, "# drand quicknet round %d\n", round)
	aw := armor.NewWriter(&buf)
	if err := tlock.New(n).Strict().Encrypt(aw, strings.NewReader(id.String()), round); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// WriteTimelock はタイムロック鍵ファイルを O_EXCL で作る。
func WriteTimelock(path string, id *age.X25519Identity, unlock time.Time) error {
	if !unlock.After(time.Now()) {
		return errors.New("開封可能日時は未来の日時を指定してください")
	}
	b, err := TimelockIdentity(id, unlock)
	if err != nil {
		return err
	}
	return writeKeyFile(path, string(b))
}

// IsTimelockFile はファイル内容がタイムロック鍵かどうかを返す。
func IsTimelockFile(b []byte) bool {
	return bytes.Contains(b, []byte(armor.Header))
}

func armoredPart(b []byte) ([]byte, error) {
	i := bytes.Index(b, []byte(armor.Header))
	if i < 0 {
		return nil, errors.New("タイムロック鍵の形式が不正です")
	}
	return b[i:], nil
}

// TimelockRound はタイムロック鍵ファイルの age ヘッダから、ロック先のラウンドを読む。
// コメント行ではなく実際の暗号文ヘッダを見るので、書き換えられていても正しい値になる。
func TimelockRound(b []byte) (uint64, error) {
	a, err := armoredPart(b)
	if err != nil {
		return 0, err
	}
	hdr, err := age.ExtractHeader(armor.NewReader(bytes.NewReader(a)))
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(hdr))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 4 && f[0] == "->" && f[1] == "tlock" {
			if f[3] != quicknetChainHash {
				return 0, errors.New("quicknet 以外のチェーンでロックされています")
			}
			return strconv.ParseUint(f[2], 10, 64)
		}
	}
	return 0, errors.New("タイムロックの情報が見つかりません")
}

// TooEarlyError は開封可能日時を添えた ErrTooEarly。
type TooEarlyError struct{ Unlock time.Time }

func (e *TooEarlyError) Error() string {
	return fmt.Sprintf("%v: 開封可能日時は %s (%s)", ErrTooEarly, e.Unlock.Local().Format("2006-01-02 15:04:05"), Remaining(e.Unlock))
}
func (e *TooEarlyError) Unwrap() error { return ErrTooEarly }

// Remaining は残り時間を人間向けに表す。
func Remaining(t time.Time) string {
	d := time.Until(t)
	switch {
	case d <= 0:
		return "開封可能になっています"
	case d < time.Minute:
		return fmt.Sprintf("あと %d 秒", int(d.Seconds())+1)
	case d < time.Hour:
		return fmt.Sprintf("あと %d 分", int(d.Minutes())+1)
	case d < 48*time.Hour:
		return fmt.Sprintf("あと %d 時間", int(d.Hours())+1)
	default:
		return fmt.Sprintf("あと %d 日", int(d.Hours()/24)+1)
	}
}

// UnlockTimelock はタイムロック鍵ファイルの内容から秘密鍵を取り出す (drand への接続が必要)。
func UnlockTimelock(b []byte) (*age.X25519Identity, error) {
	round, err := TimelockRound(b)
	if err != nil {
		return nil, err
	}
	unlock := RoundTime(round)
	// 手元の時計で明らかに早いなら、ネットワークに行くまでもない。
	// (時計を進めてもここを通過するだけで、drand が署名を出さないので開かない)
	if time.Now().Before(unlock) {
		return nil, &TooEarlyError{unlock}
	}
	n, err := newQuicknet()
	if err != nil {
		return nil, err
	}
	a, _ := armoredPart(b)
	var out bytes.Buffer
	if err := tlock.New(n).Strict().Decrypt(&out, bytes.NewReader(a)); err != nil {
		switch {
		case errors.Is(n.lastErr, ErrTooEarly):
			return nil, &TooEarlyError{unlock}
		case n.lastErr != nil:
			return nil, n.lastErr
		}
		return nil, err
	}
	return age.ParseX25519Identity(strings.TrimSpace(out.String()))
}

// ParseUnlockTime は開封可能日時の指定を解釈する。
// "2036-03-20", "2036-03-20 09:00", RFC3339, 相対指定 "+10y" "+6mo" "+30d" "+90s" "+2h" など。
func ParseUnlockTime(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "+"); ok {
		for _, u := range []struct {
			suffix  string
			y, m, d int
		}{{"y", 1, 0, 0}, {"mo", 0, 1, 0}, {"d", 0, 0, 1}} {
			if num, ok := strings.CutSuffix(rest, u.suffix); ok {
				if v, err := strconv.Atoi(num); err == nil && v > 0 {
					return now.AddDate(u.y*v, u.m*v, u.d*v), nil
				}
			}
		}
		if d, err := time.ParseDuration(rest); err == nil && d > 0 {
			return now.Add(d), nil
		}
		return time.Time{}, fmt.Errorf("相対指定の形式が不正です: %q (例: +10y, +6mo, +30d, +2h, +90s)", s)
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// 2036/3/20 や 2036.03.20 も受け付ける (日付部分の区切りだけ "-" に揃える)。
	// 書式の "1" "2" "15" は 1桁・2桁のどちらも読めるので、10-1 でも 10-01 でもよい。
	norm := s
	if date, rest, ok := strings.Cut(s, " "); ok {
		norm = strings.NewReplacer("/", "-", ".", "-").Replace(date) + " " + rest
	} else if date, rest, ok := strings.Cut(s, "T"); ok {
		norm = strings.NewReplacer("/", "-", ".", "-").Replace(date) + "T" + rest
	} else {
		norm = strings.NewReplacer("/", "-", ".", "-").Replace(s)
	}
	for _, layout := range []string{"2006-1-2T15:04:05", "2006-1-2T15:04", "2006-1-2 15:04:05", "2006-1-2 15:04", "2006-1-2"} {
		if t, err := time.ParseInLocation(layout, norm, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("日時の形式が不正です: %q\n"+
		"  書き方の例: 2036-03-20 / 2036-3-20 / 2036/3/20 (その日の 0:00)、\"2036-03-20 09:00\" (時刻付きは \"\" で囲む)、+10y (10年後)", s)
}

// ReadTimelockInfo はタイムロック鍵ファイルの開封可能日時を返す (オフライン)。
func ReadTimelockInfo(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	r, err := TimelockRound(b)
	if err != nil {
		return time.Time{}, err
	}
	return RoundTime(r), nil
}
