package vault

import (
	"testing"
	"time"

	"filippo.io/age"
)

// Fuzz の種とターゲット (M8)。パーサがパニックせずエラーを返すことだけを保証する。

func FuzzParseShare(f *testing.F) {
	id, _ := age.GenerateX25519Identity()
	if shares, err := SplitIdentity(id, 2, 3); err == nil {
		for _, s := range shares {
			f.Add(s.String())
		}
	}
	f.Add("WOTC-SHARE-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	f.Add("")
	f.Add("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	f.Fuzz(func(t *testing.T, s string) {
		share, err := ParseShare(s)
		if err == nil && share != nil {
			// 読めた欠片は再エンコードしてもパニックしないこと
			_ = share.String()
		}
	})
}

func FuzzBech32Decode(f *testing.F) {
	id, _ := age.GenerateX25519Identity()
	f.Add(id.String())
	f.Add(id.Recipient().String())
	f.Add("wotc-share-1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	f.Add("1")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _ = bech32Decode(s)
	})
}

func FuzzParseUnlockTime(f *testing.F) {
	for _, s := range []string{"2036-03-20", "+10y", "+6mo", "+30d", "+90s", "2036-03-20 09:00", "tomorrow", "", "2036-13-01", "+0d", "99999999999999999999"} {
		f.Add(s)
	}
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.Local)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseUnlockTime(s, now)
	})
}
