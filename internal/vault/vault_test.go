package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
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
