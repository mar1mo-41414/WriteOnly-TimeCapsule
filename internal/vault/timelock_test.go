package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestRoundMath(t *testing.T) {
	// genesis 直後は round 1、周期 3 秒
	if RoundTime(1).Unix() != quicknetGenesis || RoundTime(2).Unix() != quicknetGenesis+3 {
		t.Fatal("RoundTime")
	}
	for _, off := range []int64{0, 1, 2, 3, 4, 100} {
		at := time.Unix(quicknetGenesis+1000+off, 0)
		r := RoundAt(at)
		if RoundTime(r).Before(at) {
			t.Errorf("RoundAt(%v) = %d は指定時刻より前に公開される", at, r)
		}
		if RoundTime(r).Sub(at) >= 3*time.Second {
			t.Errorf("RoundAt(%v) = %d は遅すぎる", at, r)
		}
	}
}

func TestParseUnlockTime(t *testing.T) {
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.Local)
	for in, want := range map[string]time.Time{
		"2036-03-20":       time.Date(2036, 3, 20, 0, 0, 0, 0, time.Local),
		"2036-03-20 09:30": time.Date(2036, 3, 20, 9, 30, 0, 0, time.Local),
		"+10y":             time.Date(2036, 9, 29, 10, 0, 0, 0, time.Local),
		"+6mo":             time.Date(2027, 3, 29, 10, 0, 0, 0, time.Local),
		"+30d":             time.Date(2026, 10, 29, 10, 0, 0, 0, time.Local),
		"+90s":             now.Add(90 * time.Second),
		"2026-10-1":        time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local),
		"2026-10-01":       time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local),
		"2026/10/1":        time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local),
		"2026.10.01":       time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local),
		"2036-3-20 9:30":   time.Date(2036, 3, 20, 9, 30, 0, 0, time.Local),
		"2036/03/20 09:30": time.Date(2036, 3, 20, 9, 30, 0, 0, time.Local),
		"2036-3-20T09:30":  time.Date(2036, 3, 20, 9, 30, 0, 0, time.Local),
	} {
		got, err := ParseUnlockTime(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "tomorrow", "+0d", "+-3y", "2036-13-01", "2036-02-30", "20361001", "10/1/2026"} {
		if _, err := ParseUnlockTime(bad, now); err == nil {
			t.Errorf("%q を受け付けてしまった", bad)
		}
	}
}

func TestTimelockTooEarlyOffline(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	unlock := time.Now().AddDate(10, 0, 0)
	b, err := TimelockIdentity(id, unlock)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "AGE-SECRET-KEY") {
		t.Fatal("秘密鍵が平文で入っている")
	}
	r, err := TimelockRound(b)
	if err != nil || r != RoundAt(unlock) {
		t.Fatalf("round = %d, %v", r, err)
	}
	var te *TooEarlyError
	if _, err := UnlockTimelock(b); !errors.As(err, &te) || !errors.Is(err, ErrTooEarly) {
		t.Fatalf("want TooEarly, got %v", err)
	}
}

// 実際の drand に接続するテスト。VAULT_OFFLINE=1 でスキップ。
func TestTimelockDrandLive(t *testing.T) {
	if os.Getenv("VAULT_OFFLINE") != "" {
		t.Skip("VAULT_OFFLINE")
	}
	id, _ := age.GenerateX25519Identity()
	// 1分前 (公開済みのラウンド) にロック → すぐ開けるはず
	b, err := TimelockIdentity(id, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnlockTimelock(b)
	if errors.Is(err, ErrDrandUnreachable) {
		t.Skip(err)
	}
	if err != nil || got.String() != id.String() {
		t.Fatalf("unlock: %v", err)
	}

	// 手元の時計チェックをすり抜けても (= 時計を進めた想定)、drand が署名を出さないので開かない
	n, _ := newQuicknet()
	future := RoundAt(time.Now().Add(time.Hour))
	if _, err := n.Signature(future); !errors.Is(err, ErrTooEarly) {
		t.Fatalf("未来ラウンドの署名が取れてしまった/想定外のエラー: %v", err)
	}
}

func TestInitWithTimelockAndEscape(t *testing.T) {
	d := t.TempDir()
	o := InitOptions{
		Container: filepath.Join(d, "vault.dat"), PubKey: filepath.Join(d, "vault.dat.pub"),
		KeyOut: filepath.Join(d, "k", "c.key"), Size: MinSize, Threshold: 2, Shares: 3,
		Unlock: time.Now().AddDate(5, 0, 0), TimelockOut: filepath.Join(d, "vault.dat.tlock"),
	}
	_, files, err := Init(o)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := LoadRecipient(o.PubKey)
	if err := Add(o.Container, r, writeFile(t, d, "x.txt", []byte("hi"))); err != nil {
		t.Fatal(err)
	}
	// タイムロックだけ → まだ早い
	if _, err := LoadKeys([]string{o.TimelockOut}); !errors.Is(err, ErrTooEarly) {
		t.Fatalf("want TooEarly, got %v", err)
	}
	// タイムロック + 欠片1個 → どちらも駄目
	if _, err := LoadKeys([]string{o.TimelockOut, files[0]}); err == nil {
		t.Fatal("開いてしまった")
	}
	// 非常口: 欠片2個なら日付前でも開く
	id, err := LoadKeys([]string{o.TimelockOut, files[0], files[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(o.Container, id, filepath.Join(d, "out")); err != nil {
		t.Fatal(err)
	}
}
