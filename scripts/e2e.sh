#!/usr/bin/env bash
# vault CLI の通しテスト。使い方: scripts/e2e.sh [vault バイナリ]
# macOS / Linux 両対応。drand への接続が必要 (タイムロックの章)。
set -u

VAULT=$(cd "$(dirname "${1:-./vault}")" && pwd)/$(basename "${1:-./vault}")
[ -x "$VAULT" ] || { echo "vault バイナリがありません: $VAULT"; exit 2; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

PASS=0 FAIL=0
LOG="$WORK/last.log"
ok()   { PASS=$((PASS+1)); printf '  \033[32mOK\033[0m   %s\n' "$1"; }
ng()   { FAIL=$((FAIL+1)); printf '  \033[31mNG\033[0m   %s\n' "$1"; sed 's/^/         | /' "$LOG" | tail -8; }
v()    { "$VAULT" "$@" >"$LOG" 2>&1; }
yes_v(){ echo y | "$VAULT" "$@" >"$LOG" 2>&1; }
no_v() { echo n | "$VAULT" "$@" >"$LOG" 2>&1; }
# drand へ届かない状態を再現 (存在しないプロキシ経由にする)
offline_v() { HTTPS_PROXY=http://127.0.0.1:9 "$VAULT" "$@" >"$LOG" 2>&1; }
# expect_ok <説明> <cmd...> / expect_fail <説明> <エラー文言> <cmd...>
expect_ok()   { local d=$1; shift; if "$@"; then ok "$d"; else ng "$d"; fi; }
expect_fail() { local d=$1 msg=$2; shift 2; if "$@"; then ng "$d (成功してしまった)"; elif grep -q -- "$msg" "$LOG"; then ok "$d"; else ng "$d (想定外のエラー)"; fi; }
check()       { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else echo "(check: $*)" >"$LOG"; ng "$d"; fi; }
statsig()     { python3 -c 'import os,sys,hashlib;s=os.stat(sys.argv[1]);print(s.st_size,s.st_mtime_ns)' "$1"; }
filehash()    { python3 -c 'import sys,hashlib;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
gone()        { for f in "$@"; do [ ! -e "$f" ] || return 1; done; }
section()     { printf '\n\033[1m■ %s\033[0m\n' "$1"; mkdir -p "$WORK/$2"; cd "$WORK/$2"; }
mkdata()      { mkdir -p data; echo "テスト日記 $(date +%s%N)" > data/diary.txt; printf 'a,b\n1,2\n' > data/score.csv; head -c 100000 /dev/urandom > data/photo.jpg; echo "消えるメモ" > data/memo.txt; }
same_all()    { for f in "$@"; do cmp -s "data/$f" "opened/$f" || return 1; done; }

echo "vault: $VAULT ($("$VAULT" --version))"
echo "作業ディレクトリ: $WORK"

# ---------------------------------------------------------------
section "1. 通常カプセル: 作成 → 追加 → 容量切れ → 開封 → 破壊" normal
mkdata
expect_ok  "init (1MiB, 鍵の出力先ディレクトリ自動作成)" v init --size 1M --key-out usb/secret.key
check      "コンテナが 1MiB 実確保 (非スパース)" python3 -c 'import os;s=os.stat("vault.dat");assert s.st_size==1<<20 and s.st_blocks*512>=1<<20'
BEFORE=$(statsig vault.dat); H0=$(filehash vault.dat)
expect_ok  "add 3件" v add data/diary.txt data/score.csv data/photo.jpg
cp data/memo.txt memo.bak
expect_ok  "add --delete-original" v add --delete-original data/memo.txt
check      "元ファイル削除済み" gone data/memo.txt
mv memo.bak data/memo.txt
check      "追記後もサイズ・mtime 不変" test "$(statsig vault.dat)" = "$BEFORE"
check      "中身 (ハッシュ) は変化" test "$(filehash vault.dat)" != "$H0"
check      "コンテナに平文の痕跡なし" python3 -c 'import sys;b=open("vault.dat","rb").read();sys.exit(any(s.encode() in b for s in ["age-encryption","diary","テスト日記","memo","X25519"]))'
expect_ok  "status" v status
check      "status は中身の情報を出さない (一致表示のみ)" grep -q "一致" "$LOG"
head -c 400000 /dev/urandom > data/big.bin
v add data/big.bin; v add data/big.bin
expect_fail "容量切れ" "容量不足" v add data/big.bin
check      "容量切れの表示は「容量不足」だけ" test "$(grep -c . "$LOG")" -le 2
# --delete-original は「追加に成功したファイルだけ」消す。容量不足で失敗したファイルは残す
cp data/big.bin data/keep.bin; HK=$(filehash data/keep.bin)
expect_fail "容量切れ + --delete-original" "容量不足" v add --delete-original data/keep.bin
check      "容量切れで失敗した元ファイルは残る (中身も無傷)" test -e data/keep.bin -a "$(filehash data/keep.bin)" = "$HK"
echo "一緒に渡した小さいファイル" > data/mixed.txt; cp data/mixed.txt mixed.bak
expect_fail "小+大を一度に --delete-original (大だけ失敗)" "1 件の追加に失敗" v add --delete-original data/mixed.txt data/keep.bin
check      "成功した小さいファイルだけ消える" gone data/mixed.txt
check      "失敗した大きいファイルは残る (中身も無傷)" test -e data/keep.bin -a "$(filehash data/keep.bin)" = "$HK"
echo "容量切れの後" > data/after.txt
expect_ok  "容量切れ後も小さいファイルは追加できる" v add data/after.txt
expect_ok  "開封 + 破棄確認で n" no_v open --key usb/secret.key --out opened1 --and-destroy-key
check      "n ならコンテナ・鍵は残る" test -e vault.dat -a -e usb/secret.key
expect_ok  "開封 + 破棄 (y)" yes_v open --key usb/secret.key --out opened --and-destroy-key
check      "8件展開 (容量切れで失敗したものは入っていない)" grep -q "^8 件を" "$LOG"
check      "一緒に渡して成功した mixed.txt も一致" cmp -s mixed.bak opened/mixed.txt
check      "失敗した keep.bin は入っていない" gone opened/keep.bin
check      "展開物が元と一致 (同名は big (1).bin)" same_all diary.txt score.csv photo.jpg memo.txt big.bin after.txt
check      "big (1).bin も一致" cmp -s data/big.bin "opened/big (1).bin"
check      "コンテナ・秘密鍵・公開鍵が消滅" gone vault.dat usb/secret.key vault.dat.pub
expect_fail "破壊後は status できない" "no such file" v status

# ---------------------------------------------------------------
section "2. 鍵分割で作成 (2-of-3) → 分割鍵で開封・破壊" split
mkdata
expect_ok  "init --shares 3 --threshold 2" v init --size 512K --shares 3 --threshold 2 --key-out keys/c.key
check      "欠片ファイルが3つ" test -e keys/c.share1-of-3.key -a -e keys/c.share2-of-3.key -a -e keys/c.share3-of-3.key
check      "完全な秘密鍵はどこにも無い" sh -c '! grep -rq AGE-SECRET-KEY keys && test ! -e keys/c.key'
expect_ok  "add" v add data/diary.txt data/photo.jpg
expect_ok  "欠片 1+3 で開封 + 破壊" yes_v open --key keys/c.share1-of-3.key --key keys/c.share3-of-3.key --out opened --and-destroy-key
check      "展開物が一致" same_all diary.txt photo.jpg
check      "コンテナと使った欠片が消滅、未使用の欠片2は残る" sh -c 'test ! -e vault.dat -a ! -e keys/c.share1-of-3.key -a ! -e keys/c.share3-of-3.key -a -e keys/c.share2-of-3.key'

section "3. 既存の鍵を後から分割 (3-of-5) → 分割鍵で開封・破壊" split-later
mkdata
expect_ok  "init (分割なし)" v init --size 512K --key-out secret.key
expect_ok  "add" v add data/diary.txt data/score.csv
expect_ok  "split 3-of-5 --delete-original (y)" yes_v split --key secret.key --shares 5 --threshold 3 --key-out shares/s.key --delete-original
check      "元の秘密鍵は消去済み" gone secret.key
check      "欠片ファイルが5つ" test "$(ls shares | wc -l | tr -d ' ')" = 5
expect_fail "欠片2個では開かない" "足りません (3 個必要、2 個" v open --key shares/s.share2-of-5.key --key shares/s.share5-of-5.key
expect_ok  "欠片 2+4+5 で開封 + 破壊" yes_v open --key shares/s.share2-of-5.key --key shares/s.share4-of-5.key --key shares/s.share5-of-5.key --out opened --and-destroy-key
check      "展開物が一致" same_all diary.txt score.csv
check      "コンテナ消滅" gone vault.dat vault.dat.pub

# ---------------------------------------------------------------
section "4. 鍵の破損 / 不足 / 別カプセルの鍵" errors
mkdata
v init --size 256K --shares 3 --threshold 2 --key-out k/a.key
v init -V other.dat --size 256K --key-out o/other.key
v init -V other2.dat --size 256K --shares 3 --threshold 2 --key-out o/o2.key
v add data/diary.txt
# 破損: 欠片の1文字書き換え
python3 - <<'EOF'
import re
def corrupt(src, dst, pos):
    s = open(src).read()
    m = re.search(r'^(WOTC-SHARE-1|AGE-SECRET-KEY-1)\S+$', s, re.M)
    line = m.group(0); c = line[pos]
    line2 = line[:pos] + ('Q' if c != 'Q' else 'P') + line[pos+1:]
    open(dst, 'w').write(s.replace(line, line2))
corrupt('k/a.share1-of-3.key', 'typo-share.key', 40)
corrupt('o/other.key', 'typo-secret.key', 30)
EOF
printf '# 鍵っぽいけど違う\nhello world\n' > junk.key
: > empty.key
expect_fail "欠片の書き写しミス (1文字)" "チェックサム不一致" v open --key typo-share.key --key k/a.share2-of-3.key
expect_fail "秘密鍵の破損 (1文字)" "秘密鍵が壊れています" v open -V other.dat --key typo-secret.key
expect_fail "鍵でも欠片でもないファイル" "秘密鍵でも鍵の欠片でもない" v open --key junk.key
expect_fail "空の鍵ファイル" "見つかりません" v open --key empty.key
expect_fail "存在しない鍵ファイル" "no such file" v open --key nothing.key
expect_fail "欠片不足 (1個)" "足りません (2 個必要、1 個" v open --key k/a.share1-of-3.key
expect_fail "同じ欠片を2回" "足りません (2 個必要、1 個" v open --key k/a.share2-of-3.key --key k/a.share2-of-3.key
expect_fail "別カプセルの秘密鍵で開封" "鍵が一致しません" v open --key o/other.key
expect_fail "別カプセルの欠片が混入" "別のカプセル" v open --key k/a.share1-of-3.key --key o/o2.share2-of-3.key
expect_fail "別カプセルの欠片だけ揃えて開封" "鍵が一致しません" v open --key o/o2.share1-of-3.key --key o/o2.share2-of-3.key
expect_ok  "(準備) 同じ鍵を分割し直す" v split --key o/other.key --shares 3 --threshold 2 --key-out o/re1.key
expect_ok  "(準備) もう一度分割し直す" v split --key o/other.key --shares 3 --threshold 2 --key-out o/re2.key
expect_fail "分割し直した欠片の混入" "別の回に分割" v open -V other.dat --key o/re1.share1-of-3.key --key o/re2.share2-of-3.key
expect_fail "別カプセルの公開鍵で追加" "鍵が一致しません" v add --pubkey other.dat.pub data/diary.txt
expect_fail "別カプセルの鍵でタイムロック追加" "公開鍵と一致しません" v timelock --key o/other.key --until +1y
expect_fail "--shares だけ指定" "両方を指定" v init -V x.dat --shares 3
expect_fail "threshold > shares" "分割数の指定が不正" v init -V x.dat --size 64K --shares 2 --threshold 3 --key-out x/x.key
expect_fail "threshold 1" "分割数の指定が不正" v init -V x.dat --size 64K --shares 3 --threshold 1 --key-out x/x.key
check      "失敗した init はファイルを残さない" gone x.dat x.dat.pub x
expect_ok  "エラーの後も正しい欠片なら開ける" v open --key k/a.share3-of-3.key --key k/a.share1-of-3.key --out opened
check      "展開物が一致" same_all diary.txt

# ---------------------------------------------------------------
section "5. タイムロック: 作成 → 日時前 → 非常口 → 疎通不可 → 日時後に開封・破壊" timelock
mkdata
expect_ok  "init --timelock +40s + 非常口 2-of-3" v init --size 512K --timelock +40s --shares 3 --threshold 2 --key-out escape/c.key
T0=$(date +%s)
check      ".tlock に秘密鍵が平文で入っていない" sh -c '! grep -q AGE-SECRET-KEY vault.dat.tlock'
expect_ok  "add" v add data/diary.txt data/photo.jpg
expect_ok  "status に開封可能日時" v status
check      "status に「あと N 秒」" grep -q "開封可能 (あと" "$LOG"
expect_fail "日時前: 鍵指定なし (.tlock)" "まだ開封できません" v open
check      "日時前のエラーに非常口の案内" grep -q "非常口" "$LOG"
expect_fail "日時前: .tlock + 欠片1個" "まだ開封できません" v open --key vault.dat.tlock --key escape/c.share1-of-3.key
expect_fail "日時前: 疎通不可でも「まだ」(ネットワーク不要)" "まだ開封できません" offline_v open
expect_ok  "非常口: 日時前でも欠片2個で開封 (破棄なし)" v open --key escape/c.share2-of-3.key --key escape/c.share3-of-3.key --out early
check      "非常口の展開物が一致" sh -c 'cmp -s data/diary.txt early/diary.txt && cmp -s data/photo.jpg early/photo.jpg'
expect_ok  "既存カプセル: 別ファイルに10年ロック追加" v timelock --key escape/c.share1-of-3.key --key escape/c.share2-of-3.key --until +10y --out ten.tlock
check      "10年ロックは約3650日後" grep -q "あと 365[0-9] 日" "$LOG"
expect_fail "10年ロックでは開かない" "まだ開封できません" v open --key ten.tlock
expect_fail "過去日時のタイムロックは作れない" "未来の日時" v timelock --key escape/c.share1-of-3.key --key escape/c.share2-of-3.key --until 2020-01-01 --out past.tlock
expect_fail "不正な日時形式" "形式が不正" v init -V y.dat --size 64K --timelock tomorrow --key-out y.key
W=$(( 45 - ($(date +%s) - T0) )); [ $W -gt 0 ] && { echo "  … 開封可能日時まで ${W} 秒待機"; sleep $W; }
expect_ok  "日時後: status は開封可能" v status
check      "「開封可能になっています」" grep -q "開封可能になっています" "$LOG"
expect_fail "日時後: drand 疎通不可 (プロキシで遮断)" "drand ネットワークに接続できません" offline_v open --out x
check      "疎通不可のエラーは簡潔 (3行以内) で非常口を案内" sh -c "test \$(grep -c . '$LOG') -le 3 && grep -q 非常口 '$LOG'"
check      "疎通不可では何も展開・破棄しない" sh -c 'test ! -e x -a -e vault.dat -a -e vault.dat.tlock'
expect_ok  "日時後: 鍵指定なしで開封 + 破壊" yes_v open --out opened --and-destroy-key
check      "展開物が一致" same_all diary.txt photo.jpg
check      "コンテナ・.tlock・公開鍵が消滅" gone vault.dat vault.dat.tlock vault.dat.pub

# ---------------------------------------------------------------
printf '\n\033[1m結果: %d OK / %d NG\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
