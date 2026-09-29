package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestBech32AgeCompat(t *testing.T) {
	for range 20 {
		id, _ := age.GenerateX25519Identity()
		b, err := identityBytes(id)
		if err != nil {
			t.Fatal(err)
		}
		back, err := identityFromBytes(b)
		if err != nil || back.String() != id.String() {
			t.Fatalf("roundtrip mismatch: %v", err)
		}
	}
}

// combinations は n 個から k 個以上を選ぶ全ての組み合わせ (添字) を返す。
func subsets(n int) [][]int {
	var out [][]int
	for mask := 1; mask < 1<<n; mask++ {
		var s []int
		for i := range n {
			if mask>>i&1 == 1 {
				s = append(s, i)
			}
		}
		out = append(out, s)
	}
	return out
}

func TestSplitCombineAllSubsets(t *testing.T) {
	for _, c := range []struct{ k, n int }{{2, 2}, {2, 3}, {3, 5}, {4, 6}} {
		id, _ := age.GenerateX25519Identity()
		shares, err := SplitIdentity(id, c.k, c.n)
		if err != nil {
			t.Fatal(err)
		}
		for _, sub := range subsets(c.n) {
			var picked []*Share
			for _, i := range sub {
				// 文字列を経由して、実際のファイル内容と同じ経路で読む
				s, err := ParseShare(shares[i].String())
				if err != nil {
					t.Fatal(err)
				}
				picked = append(picked, s)
			}
			got, err := CombineShares(picked)
			if len(sub) >= c.k {
				if err != nil || got.String() != id.String() {
					t.Errorf("%d-of-%d %v: 復元できない: %v", c.k, c.n, sub, err)
				}
			} else if err == nil {
				t.Errorf("%d-of-%d %v: 足りないのに復元できた", c.k, c.n, sub)
			}
		}
	}
}

func TestShareErrors(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	sa, _ := SplitIdentity(a, 2, 3)
	sb, _ := SplitIdentity(b, 2, 3)

	if _, err := CombineShares([]*Share{sa[0], sb[1]}); err == nil || !strings.Contains(err.Error(), "別のカプセル") {
		t.Errorf("混入を検出できない: %v", err)
	}
	sa2, _ := SplitIdentity(a, 2, 3)
	if _, err := CombineShares([]*Share{sa[0], sa2[1]}); err == nil || !strings.Contains(err.Error(), "別の回に分割") {
		t.Errorf("分割し直した欠片の混入を検出できない: %v", err)
	}
	if _, err := CombineShares([]*Share{sa[0], sa[0]}); err == nil || !strings.Contains(err.Error(), "足りません") {
		t.Errorf("重複を不足として扱えない: %v", err)
	}
	// 1文字の書き写し間違いはチェックサムで弾く
	str := sa[0].String()
	i := len(str) - 10
	typo := str[:i] + map[bool]string{true: "Q", false: "P"}[str[i] != 'Q'] + str[i+1:]
	if _, err := ParseShare(typo); err == nil {
		t.Error("書き写し間違いを検出できない")
	}
	// 小文字で書き写しても読める
	if _, err := ParseShare(strings.ToLower(str)); err != nil {
		t.Errorf("小文字の欠片が読めない: %v", err)
	}
	for _, c := range [][2]int{{1, 3}, {4, 3}, {2, 256}} {
		if _, err := SplitIdentity(a, c[0], c[1]); err == nil {
			t.Errorf("%d-of-%d を拒否できない", c[0], c[1])
		}
	}
}

func TestInitSplitAndOpen(t *testing.T) {
	d := t.TempDir()
	o := InitOptions{
		Container: filepath.Join(d, "vault.dat"), PubKey: filepath.Join(d, "vault.dat.pub"),
		KeyOut: filepath.Join(d, "keys", "secret.key"), Size: MinSize, Threshold: 2, Shares: 3,
	}
	_, files, err := Init(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 || filepath.Base(files[1]) != "secret.share2-of-3.key" {
		t.Fatalf("files = %v", files)
	}
	// 完全な秘密鍵はどこにも書かれていないこと
	if _, err := os.Stat(o.KeyOut); !os.IsNotExist(err) {
		t.Fatal("分割時に完全な秘密鍵が書かれている")
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "AGE-SECRET-KEY") {
			t.Fatalf("%s に秘密鍵が含まれている", f)
		}
	}

	r, _ := LoadRecipient(o.PubKey)
	if err := Add(o.Container, r, writeFile(t, d, "note.txt", []byte("split!"))); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(files[:1]); err == nil {
		t.Fatal("欠片1個で鍵が復元できた")
	}
	id, err := LoadKeys([]string{files[2], files[0]})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(o.Container, id, filepath.Join(d, "out"))
	if err != nil || len(opened) != 1 {
		t.Fatalf("opened=%d err=%v", len(opened), err)
	}
	// 欠片2個を1ファイルにまとめても読める
	b1, _ := os.ReadFile(files[0])
	b2, _ := os.ReadFile(files[1])
	both := writeFile(t, d, "both.txt", append(b1, b2...))
	if _, err := LoadKeys([]string{both}); err != nil {
		t.Fatal(err)
	}
}
