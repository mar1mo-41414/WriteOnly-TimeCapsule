package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// H2: スーパーブロックの二重化 (A面 = 従来の v1 形式 [0,72)、
// B面 = 同じ構造の複写をコンテナ末尾 [size-72, size) に配置)。

// A面の salt / nonce / seal のいずれを壊しても、B面から復旧して開封できること。
func TestSuperblockBackupRecovery(t *testing.T) {
	for _, off := range []int64{0, 20, 50} { // salt / nonce / seal
		fx := newVault(t, 1<<20)
		r, _ := LoadRecipient(fx.pub)
		src := t.TempDir()
		if err := Add(fx.container, r, writeFile(t, src, "a.txt", []byte("first"))); err != nil {
			t.Fatal(err)
		}
		if err := Add(fx.container, r, writeFile(t, src, "b.txt", []byte("second"))); err != nil {
			t.Fatal(err)
		}
		id, _ := LoadIdentity(fx.sec)
		if err := Verify(fx.container, r); err != nil {
			t.Fatal(err)
		}
		corruptAt(t, fx.container, off)
		opened, err := Open(fx.container, id, filepath.Join(fx.dir, "out"))
		if err != nil {
			t.Fatalf("off=%d: B面から復旧できない: %v", off, err)
		}
		if len(opened) != 2 {
			t.Fatalf("off=%d: opened=%d", off, len(opened))
		}
		if got, _ := os.ReadFile(filepath.Join(fx.dir, "out", "b.txt")); string(got) != "second" {
			t.Fatalf("off=%d: b.txt = %q", off, got)
		}
		// 復旧した状態でさらに追記でき、その後 A面が正に戻ること
		if err := Add(fx.container, r, writeFile(t, src, "c.txt", []byte("third"))); err != nil {
			t.Fatalf("off=%d: 復旧後の追記に失敗: %v", off, err)
		}
		opened, err = Open(fx.container, id, filepath.Join(fx.dir, "out2"))
		if err != nil || len(opened) != 3 {
			t.Fatalf("off=%d: opened=%d err=%v", off, len(opened), err)
		}
	}
}

// A面も B面も壊れたら従来どおり ErrMismatch で失敗すること。
func TestSuperblockBothBroken(t *testing.T) {
	fx := newVault(t, MinSize)
	r, _ := LoadRecipient(fx.pub)
	if err := Add(fx.container, r, writeFile(t, t.TempDir(), "a.txt", []byte("x"))); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(fx.container)
	corruptAt(t, fx.container, 10)
	corruptAt(t, fx.container, st.Size()-10)
	id, _ := LoadIdentity(fx.sec)
	if _, err := Open(fx.container, id, filepath.Join(fx.dir, "out")); !errors.Is(err, ErrMismatch) {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
	if err := Verify(fx.container, r); !errors.Is(err, ErrMismatch) {
		t.Fatalf("verify: want ErrMismatch, got %v", err)
	}
}

// クラッシュ相当: A面だけ更新されて B面が旧い状態では、B面の used (旧) で
// 復旧し、新しい used を誤って採用しないこと。その Add は無かったことになるが、
// 既存レコードは無事なこと。
func TestSuperblockStaleBackupRecovery(t *testing.T) {
	fx := newVault(t, 1<<20)
	r, _ := LoadRecipient(fx.pub)
	src := t.TempDir()
	if err := Add(fx.container, r, writeFile(t, src, "first.txt", []byte("first"))); err != nil {
		t.Fatal(err)
	}
	// A面だけを更新する (B面は used=1件 のまま) = A書込み直後のクラッシュ相当
	writeRawRecord(t, fx, Meta{Name: "second.txt", Size: 6, Mode: 0o644, AddedAt: time.Now()}, []byte("second"))
	// その状態で A面を壊すと、B面の状態 (1件) で復旧する
	corruptAt(t, fx.container, 30)
	id, _ := LoadIdentity(fx.sec)
	opened, err := Open(fx.container, id, filepath.Join(fx.dir, "out"))
	if err != nil {
		t.Fatalf("復旧できない: %v", err)
	}
	if len(opened) != 1 || opened[0].Meta.Name != "first.txt" {
		t.Fatalf("opened=%v (古い used が正のはず)", opened)
	}
}

// A面が正常なら、B面が古くても A面が正であること (誤復旧しない)。
func TestSuperblockPrimaryPreferred(t *testing.T) {
	fx := newVault(t, 1<<20)
	r, _ := LoadRecipient(fx.pub)
	src := t.TempDir()
	if err := Add(fx.container, r, writeFile(t, src, "first.txt", []byte("first"))); err != nil {
		t.Fatal(err)
	}
	writeRawRecord(t, fx, Meta{Name: "second.txt", Size: 6, Mode: 0o644, AddedAt: time.Now()}, []byte("second"))
	id, _ := LoadIdentity(fx.sec)
	opened, err := Open(fx.container, id, filepath.Join(fx.dir, "out"))
	if err != nil || len(opened) != 2 {
		t.Fatalf("opened=%d err=%v (A面の2件が正のはず)", len(opened), err)
	}
}

// コメント付きコンテナで、B面がコメント領域を壊さないこと、
// A面破損時もコメントと中身の両方が読めること。
func TestSuperblockBackupWithComment(t *testing.T) {
	d := t.TempDir()
	o := InitOptions{
		Container: filepath.Join(d, "vault.dat"), PubKey: filepath.Join(d, "vault.dat.pub"),
		KeyOut: filepath.Join(d, "secret.key"), Size: 1 << 20, Comment: "B面テスト用コメント",
	}
	if _, _, err := Init(o); err != nil {
		t.Fatal(err)
	}
	r, _ := LoadRecipient(o.PubKey)
	if err := Add(o.Container, r, writeFile(t, d, "x.txt", []byte("data"))); err != nil {
		t.Fatal(err)
	}
	if err := SetComment(o.Container, r, "書き換え後のコメント"); err != nil {
		t.Fatal(err)
	}
	corruptAt(t, o.Container, 40)
	if c, ok, err := ReadComment(o.Container); err != nil || !ok || c != "書き換え後のコメント" {
		t.Fatalf("comment = %q ok=%v err=%v", c, ok, err)
	}
	id, _ := LoadIdentity(o.KeyOut)
	opened, err := Open(o.Container, id, filepath.Join(d, "out"))
	if err != nil || len(opened) != 1 {
		t.Fatalf("opened=%d err=%v", len(opened), err)
	}
}

// B面を置く場所が無い (データ領域の末尾72バイト以内まで埋まっている)
// コンテナでは writeSuperblockBackup が errBackupNoSpace を返すこと。
func TestSuperblockBackupNoSpace(t *testing.T) {
	fx := newVault(t, MinSize)
	f, err := os.OpenFile(fx.container, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, _ := LoadRecipient(fx.pub)
	sb, err := readSuperblock(f, r.String())
	if err != nil {
		t.Fatal(err)
	}
	// ちょうど末尾72バイトが空く used なら置ける
	sb.used = MinSize - superblockSize - backupSize
	if err := writeSuperblockBackup(f, sb); err != nil {
		t.Fatalf("置けるはず: %v", err)
	}
	// 1バイトでもはみ出せば置けない
	sb.used++
	if err := writeSuperblockBackup(f, sb); !errors.Is(err, errBackupNoSpace) {
		t.Fatalf("want errBackupNoSpace, got %v", err)
	}
}
