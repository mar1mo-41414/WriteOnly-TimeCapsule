package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	dir, container, pub, sec string
}

func newVault(t *testing.T, size int64) fixture {
	t.Helper()
	d := t.TempDir()
	fx := fixture{d, filepath.Join(d, "vault.dat"), filepath.Join(d, "vault.dat.pub"), filepath.Join(d, "secret.key")}
	if _, _, err := Init(InitOptions{Container: fx.container, PubKey: fx.pub, KeyOut: fx.sec, Size: size}); err != nil {
		t.Fatal(err)
	}
	return fx
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestRoundTrip(t *testing.T) {
	fx := newVault(t, 1<<20)
	r, err := LoadRecipient(fx.pub)
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	files := map[string][]byte{
		"a.txt":   []byte("hello capsule"),
		"b.bin":   randBytes(200_000),
		"empty":   {},
		"dup.txt": []byte("first"),
	}
	before, _ := os.Stat(fx.container)
	time.Sleep(10 * time.Millisecond)
	for name, data := range files {
		if err := Add(fx.container, r, writeFile(t, src, name, data)); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	// 同名ファイルは別名で展開されること
	src2 := t.TempDir()
	if err := Add(fx.container, r, writeFile(t, src2, "dup.txt", []byte("second"))); err != nil {
		t.Fatal(err)
	}

	after, _ := os.Stat(fx.container)
	if after.Size() != before.Size() {
		t.Errorf("size changed: %d -> %d", before.Size(), after.Size())
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("mtime changed: %v -> %v", before.ModTime(), after.ModTime())
	}

	id, err := LoadIdentity(fx.sec)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(fx.dir, "out")
	opened, err := Open(fx.container, id, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != len(files)+1 {
		t.Fatalf("opened %d records", len(opened))
	}
	for name, data := range files {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s: content mismatch", name)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(out, "dup (1).txt")); string(got) != "second" {
		t.Errorf("dup (1).txt = %q", got)
	}
}

func TestNoPlaintextMarkers(t *testing.T) {
	fx := newVault(t, 256<<10)
	r, _ := LoadRecipient(fx.pub)
	marker := []byte("VERY-SECRET-MARKER-1234567890")
	if err := Add(fx.container, r, writeFile(t, t.TempDir(), "secret-name.txt", marker)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(fx.container)
	for _, s := range []string{"age-encryption.org", "X25519", "secret-name", string(marker), "---"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("container contains %q", s)
		}
	}
}

func TestNoSpace(t *testing.T) {
	fx := newVault(t, MinSize)
	r, _ := LoadRecipient(fx.pub)
	src := t.TempDir()
	if err := Add(fx.container, r, writeFile(t, src, "small", []byte("ok"))); err != nil {
		t.Fatal(err)
	}
	err := Add(fx.container, r, writeFile(t, src, "big", randBytes(MinSize)))
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("want ErrNoSpace, got %v", err)
	}
	// 失敗後も既存レコードが読めること、さらに追記もできること
	if err := Add(fx.container, r, writeFile(t, src, "small2", []byte("ok2"))); err != nil {
		t.Fatal(err)
	}
	id, _ := LoadIdentity(fx.sec)
	opened, err := Open(fx.container, id, filepath.Join(fx.dir, "out"))
	if err != nil || len(opened) != 2 {
		t.Fatalf("opened=%d err=%v", len(opened), err)
	}
}

func TestWrongKey(t *testing.T) {
	fx := newVault(t, MinSize)
	other := newVault(t, MinSize)
	r, _ := LoadRecipient(other.pub)
	if err := Add(fx.container, r, writeFile(t, t.TempDir(), "x", []byte("x"))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
	id, _ := LoadIdentity(other.sec)
	if _, err := Open(fx.container, id, filepath.Join(fx.dir, "out")); !errors.Is(err, ErrMismatch) {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
}

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"../../etc/passwd": "passwd",
		"..":               "file",
		"":                 "file",
		`..\..\win.ini`:    "win.ini",
		"normal.txt":       "normal.txt",
	} {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShred(t *testing.T) {
	d := t.TempDir()
	p := writeFile(t, d, "gone", randBytes(10000))
	if err := Shred(p); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 0 {
		t.Fatalf("leftover: %v", ents)
	}
}

func TestConcurrentAdd(t *testing.T) {
	fx := newVault(t, 4<<20)
	r, _ := LoadRecipient(fx.pub)
	src := t.TempDir()
	const n = 20
	want := map[string][]byte{}
	errs := make(chan error, n)
	for i := range n {
		name := "f" + strconv.Itoa(i)
		want[name] = randBytes(30000 + i)
		p := writeFile(t, src, name, want[name])
		go func() { errs <- Add(fx.container, r, p) }()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	id, _ := LoadIdentity(fx.sec)
	out := filepath.Join(fx.dir, "out")
	opened, err := Open(fx.container, id, out)
	if err != nil || len(opened) != n {
		t.Fatalf("opened=%d err=%v (同時追加でデータが壊れた)", len(opened), err)
	}
	for name, data := range want {
		if got, _ := os.ReadFile(filepath.Join(out, name)); !bytes.Equal(got, data) {
			t.Errorf("%s が一致しない", name)
		}
	}
}

// corruptAt はコンテナの off バイト目を1ビット反転させる。
func corruptAt(t *testing.T, path string, off int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, 1)
	f.ReadAt(b, off)
	b[0] ^= 1
	f.WriteAt(b, off)
}

func TestCorruptRecordSalvage(t *testing.T) {
	fx := newVault(t, 1<<20)
	r, _ := LoadRecipient(fx.pub)
	src := t.TempDir()
	// 1件目を大きくして、そのど真ん中を壊す
	for _, f := range []struct {
		name string
		data []byte
	}{{"big", randBytes(20000)}, {"two", []byte("2")}, {"three", []byte("3")}} {
		if err := Add(fx.container, r, writeFile(t, src, f.name, f.data)); err != nil {
			t.Fatal(err)
		}
	}
	id, _ := LoadIdentity(fx.sec)

	body := filepath.Join(fx.dir, "body.dat")
	copyFile(t, fx.container, body)
	corruptAt(t, body, superblockSize+lenPrefixSize+10000)
	opened, err := Open(body, id, filepath.Join(fx.dir, "o1"))
	var ce *CorruptError
	if !errors.As(err, &ce) || len(ce.Broken) != 1 || ce.Broken[0] != 1 || ce.TruncatedAt != 0 {
		t.Fatalf("err = %v", err)
	}
	if len(opened) != 2 || opened[0].Meta.Name != "two" || opened[1].Meta.Name != "three" {
		t.Fatalf("救出できたのは %d 件", len(opened))
	}
	if _, err := os.Stat(filepath.Join(fx.dir, "o1", "big")); !os.IsNotExist(err) {
		t.Error("壊れたファイルの途中までの内容が残っている")
	}

	// 長さ情報が壊れると、それ以降は読めない
	lp := filepath.Join(fx.dir, "lp.dat")
	copyFile(t, fx.container, lp)
	corruptAt(t, lp, superblockSize+3)
	_, err = Open(lp, id, filepath.Join(fx.dir, "o2"))
	if !errors.As(err, &ce) || ce.TruncatedAt != 1 {
		t.Fatalf("err = %v", err)
	}

	// スーパーブロックが壊れると鍵の不一致と区別できない (どちらも ErrMismatch)
	sb := filepath.Join(fx.dir, "sb.dat")
	copyFile(t, fx.container, sb)
	corruptAt(t, sb, 50)
	if _, err := Open(sb, id, filepath.Join(fx.dir, "o3")); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v", err)
	}
	if err := Add(sb, r, writeFile(t, src, "x", []byte("x"))); !errors.Is(err, ErrMismatch) {
		t.Fatalf("壊れたスーパーブロックに追記できてしまった: %v", err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCreateUniqueDotfile(t *testing.T) {
	d := t.TempDir()
	var names []string
	for range 3 {
		f, p, err := createUnique(d, ".hidden", 0o600)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		names = append(names, filepath.Base(p))
	}
	if strings.Join(names, ",") != ".hidden,.hidden (1),.hidden (2)" {
		t.Errorf("names = %v", names)
	}
}

func TestAddRejectsNonRegular(t *testing.T) {
	fx := newVault(t, MinSize)
	r, _ := LoadRecipient(fx.pub)
	if err := Add(fx.container, r, t.TempDir()); err == nil {
		t.Error("ディレクトリを追加できてしまった")
	}
	if err := Add(fx.container, r, filepath.Join(fx.dir, "nothing")); err == nil {
		t.Error("存在しないファイルを追加できてしまった")
	}
}
