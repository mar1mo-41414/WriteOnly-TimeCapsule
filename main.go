// vault: 書き込み専用のタイムカプセル CLI。
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mar1mo-41414/WriteOnly-TimeCapsule/internal/vault"
)

var version = "dev"

var (
	containerPath string
	pubPath       string
)

func main() {
	root := &cobra.Command{
		Use:   "vault",
		Short: "書き込み専用タイムカプセル: 追記はできるが、秘密鍵で開封するまで中身は一切見えない",
		Long: "書き込み専用タイムカプセル: 追記はできるが、秘密鍵で開封するまで中身は一切見えない。\n\n" +
			"※ 日常をちょっと彩るための遊び道具です。実務・業務や、失うと困るデータには使わないでください。\n" +
			"   This is a toy for everyday fun. Do NOT use it for real work.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	def := os.Getenv("VAULT_PATH")
	if def == "" {
		def = "vault.dat"
	}
	root.PersistentFlags().StringVarP(&containerPath, "vault", "V", def, "コンテナファイル (環境変数 VAULT_PATH でも指定可)")
	root.PersistentFlags().StringVar(&pubPath, "pubkey", "", "公開鍵ファイル (既定: <コンテナ>.pub)")
	root.AddCommand(initCmd(), addCmd(), statusCmd(), openCmd(), splitCmd(), timelockCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "エラー:", err)
		os.Exit(1)
	}
}

func timelockPath() string {
	return containerPath + ".tlock"
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func confirm(prompt string) bool {
	fmt.Print(prompt + " [y/N] ")
	ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(ans))
	return a == "y" || a == "yes"
}

// requireContainer はコンテナが無いときに分かりやすいエラーを返す。
func requireContainer() error {
	if fileExists(containerPath) {
		return nil
	}
	return fmt.Errorf("カプセルが見つかりません: %s (別の場所にある場合は -V <パス> か環境変数 VAULT_PATH で指定してください)", containerPath)
}

// isOwnFile は p がこのカプセル自身の管理ファイル (コンテナ・公開鍵・タイムロック鍵) かどうかを返す。
func isOwnFile(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	for _, own := range []string{containerPath, pubkeyPath(), timelockPath()} {
		if ost, err := os.Stat(own); err == nil && os.SameFile(st, ost) {
			return true
		}
	}
	return false
}

func pubkeyPath() string {
	if pubPath != "" {
		return pubPath
	}
	return containerPath + ".pub"
}

func initCmd() *cobra.Command {
	var sizeStr, keyOut, unlockStr, tlockOut string
	var threshold, shares int
	c := &cobra.Command{
		Use:   "init",
		Short: "鍵ペアを生成し、固定サイズのコンテナを確保する",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkSplitFlags(cmd, threshold, shares); err != nil {
				return err
			}
			size, err := parseSize(sizeStr)
			if err != nil {
				return err
			}
			var unlock time.Time
			if unlockStr != "" {
				if unlock, err = vault.ParseUnlockTime(unlockStr, time.Now()); err != nil {
					return err
				}
			}
			if tlockOut == "" {
				tlockOut = timelockPath()
			}
			for _, p := range []string{containerPath, pubkeyPath(), tlockOut} {
				if fileExists(p) {
					return fmt.Errorf("ここには既にカプセルがあります: %s (上書きはしません。別の場所で実行するか、-V で別の名前を指定してください)", p)
				}
			}
			recipient, files, err := vault.Init(vault.InitOptions{
				Container: containerPath, PubKey: pubkeyPath(), KeyOut: keyOut,
				Size: size, Threshold: threshold, Shares: shares,
				Unlock: unlock, TimelockOut: tlockOut,
			})
			if err != nil {
				return err
			}
			fmt.Printf("コンテナを作成しました: %s (%s)\n", containerPath, sizeStr)
			fmt.Printf("公開鍵:   %s\n          %s\n", pubkeyPath(), recipient)
			if !unlock.IsZero() {
				printTimelock(tlockOut)
				fmt.Println("以下の鍵は「非常口」です (drand が使えなくなったときや、どうしても早く開けたいとき用)。")
				fmt.Println()
			}
			if threshold == 0 {
				fmt.Printf("秘密鍵:   %s\n", keyOut)
				fmt.Println()
				fmt.Println("!! 秘密鍵はこの端末から移動してください (USBメモリ・オフライン端末・紙など)。")
				fmt.Println("!! 秘密鍵を失うとコンテナは二度と開封できません。")
				return nil
			}
			printShares(files, threshold, shares, true)
			return nil
		},
	}
	c.Flags().StringVar(&sizeStr, "size", "500M", "コンテナの容量 (例: 100M, 1G)")
	c.Flags().StringVar(&keyOut, "key-out", "vault-secret.key", "秘密鍵の出力先 (分割時は欠片ファイル名の元になる)")
	c.Flags().StringVar(&unlockStr, "timelock", "", "この日時まで開封できないタイムロック鍵も作る (例: 2036-03-20, +10y)")
	c.Flags().StringVar(&tlockOut, "timelock-out", "", "タイムロック鍵の出力先 (既定: <コンテナ>.tlock)")
	addSplitFlags(c, &threshold, &shares)
	return c
}

func printTimelock(path string) {
	unlock, err := vault.ReadTimelockInfo(path)
	if err != nil {
		fmt.Printf("タイムロック: %s (読み込めません: %v)\n", path, err)
		return
	}
	fmt.Printf("タイムロック: %s\n", path)
	fmt.Printf("          %s 以降に開封可能 (%s)\n", unlock.Local().Format("2006-01-02 15:04:05"), vault.Remaining(unlock))
	fmt.Println("          この鍵はコンテナの隣に置いたままで大丈夫です。日時が来るまで誰にも (作った本人にも) 開けられません。")
	fmt.Println("          開封時は drand ネットワーク (インターネット) への接続が必要です。")
	fmt.Println()
}

func timelockCmd() *cobra.Command {
	var keyPaths []string
	var unlockStr, out string
	c := &cobra.Command{
		Use:   "timelock",
		Short: "既存のカプセルに、指定日時まで開封できないタイムロック鍵を追加する",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			unlock, err := vault.ParseUnlockTime(unlockStr, time.Now())
			if err != nil {
				return err
			}
			id, err := vault.LoadKeys(keyPaths)
			if err != nil {
				return err
			}
			if r, err := vault.LoadRecipient(pubkeyPath()); err == nil && r.String() != id.Recipient().String() {
				return errors.New("鍵がこのコンテナの公開鍵と一致しません")
			}
			if out == "" {
				out = timelockPath()
			}
			if err := vault.WriteTimelock(out, id, unlock); err != nil {
				return err
			}
			printTimelock(out)
			fmt.Printf("元の鍵ファイル (%s) は非常口として残っています。\n", strings.Join(keyPaths, ", "))
			fmt.Println("本当に日時まで開けたくないなら、それらはこの端末から移すか、分割して人に預けてください。")
			return nil
		},
	}
	c.Flags().StringArrayVar(&keyPaths, "key", nil, "秘密鍵または鍵の欠片ファイル (必須、欠片は必要数ぶん繰り返す)")
	c.Flags().StringVar(&unlockStr, "until", "", "開封可能日時 (必須、例: 2036-03-20, \"2036-03-20 09:00\", +10y)")
	c.Flags().StringVar(&out, "out", "", "タイムロック鍵の出力先 (既定: <コンテナ>.tlock)")
	c.MarkFlagRequired("key")
	c.MarkFlagRequired("until")
	return c
}

func addSplitFlags(c *cobra.Command, threshold, shares *int) {
	c.Flags().IntVar(shares, "shares", 0, "秘密鍵を N 個の欠片に分割する (--threshold と併用)")
	c.Flags().IntVar(threshold, "threshold", 0, "開封に必要な欠片の数 K (2 ≦ K ≦ N)")
}

func checkSplitFlags(cmd *cobra.Command, threshold, shares int) error {
	if cmd.Flags().Changed("shares") != cmd.Flags().Changed("threshold") {
		return errors.New("鍵を分割するには --shares と --threshold の両方を指定してください")
	}
	return nil
}

func printShares(files []string, threshold, shares int, fromInit bool) {
	fmt.Printf("鍵の欠片: %d 個 (うち %d 個集めると開封できます)\n", shares, threshold)
	for _, f := range files {
		fmt.Printf("          %s\n", f)
	}
	fmt.Println()
	if fromInit {
		fmt.Println("!! 完全な秘密鍵はどこにも保存していません。")
	}
	fmt.Println("!! 欠片はそれぞれ別の場所・別の人へ移し、この端末からは消してください。")
	fmt.Printf("!! %d 個より多く失うと (= 残りが %d 個未満になると) 二度と開封できません。\n", shares-threshold, threshold)
	fmt.Printf("!! 逆に、誰かが %d 個集めればいつでも開封できます。\n", threshold)
}

func addCmd() *cobra.Command {
	var deleteOriginal bool
	c := &cobra.Command{
		Use:   "add <file...>",
		Short: "ファイルを暗号化してコンテナに追記する",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, files []string) error {
			if err := requireContainer(); err != nil {
				return err
			}
			r, err := vault.LoadRecipient(pubkeyPath())
			if err != nil {
				return err
			}
			failed := 0
			for _, p := range files {
				if isOwnFile(p) {
					fmt.Fprintf(os.Stderr, "スキップ: %s はこのカプセル自身のファイルです\n", p)
					continue
				}
				if err := vault.Add(containerPath, r, p); err != nil {
					failed++
					if errors.Is(err, vault.ErrNoSpace) {
						err = vault.ErrNoSpace // 残量のヒントになる情報は出さない
					}
					fmt.Fprintf(os.Stderr, "失敗: %s: %v\n", p, err)
					continue
				}
				if deleteOriginal {
					if err := vault.Shred(p); err != nil {
						fmt.Fprintf(os.Stderr, "警告: %s は追加済みですが元ファイルの削除に失敗: %v\n", p, err)
					}
				}
				fmt.Printf("追加しました: %s\n", p)
			}
			if failed > 0 {
				return fmt.Errorf("%d 件の追加に失敗しました", failed)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&deleteOriginal, "delete-original", false, "追加成功後に元ファイルを上書き消去する")
	return c
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "コンテナの存在と外形サイズだけを表示する",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireContainer(); err != nil {
				return err
			}
			st, err := os.Stat(containerPath)
			if err != nil {
				return err
			}
			fmt.Printf("コンテナ: %s\n", containerPath)
			fmt.Printf("サイズ:   %d バイト (外形。中身の量とは無関係)\n", st.Size())
			r, err := vault.LoadRecipient(pubkeyPath())
			if err != nil {
				fmt.Printf("公開鍵:   読み込めません (%v)\n", err)
				return nil
			}
			if err := vault.Verify(containerPath, r); err != nil {
				fmt.Printf("公開鍵:   %s (不一致: %v)\n", pubkeyPath(), err)
				return nil
			}
			fmt.Printf("公開鍵:   %s (一致)\n", pubkeyPath())
			if fileExists(timelockPath()) {
				unlock, err := vault.ReadTimelockInfo(timelockPath())
				if err != nil {
					fmt.Printf("タイムロック: %s (読み込めません: %v)\n", timelockPath(), err)
				} else {
					fmt.Printf("タイムロック: %s 以降に開封可能 (%s)\n", unlock.Local().Format("2006-01-02 15:04:05"), vault.Remaining(unlock))
				}
			}
			return nil
		},
	}
}

func openCmd() *cobra.Command {
	var keyPaths []string
	var outDir string
	var destroy bool
	c := &cobra.Command{
		Use:   "open",
		Short: "秘密鍵でコンテナを開封し、全ファイルを展開する",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireContainer(); err != nil {
				return err
			}
			if len(keyPaths) == 0 {
				if !fileExists(timelockPath()) {
					return errors.New("--key で秘密鍵・鍵の欠片・タイムロック鍵のいずれかを指定してください")
				}
				keyPaths = []string{timelockPath()}
			}
			id, err := vault.LoadKeys(keyPaths)
			if errors.Is(err, vault.ErrTooEarly) || errors.Is(err, vault.ErrDrandUnreachable) {
				return fmt.Errorf("%w\n(非常口: 秘密鍵、または鍵の欠片を必要数 --key で渡せば今すぐ開けられます)", err)
			}
			if err != nil {
				return err
			}
			if outDir == "" {
				outDir = "vault-opened-" + time.Now().Format("20060102-150405")
			}
			opened, err := vault.Open(containerPath, id, outDir)
			for _, o := range opened {
				fmt.Printf("%s  %10d  %s\n", o.Meta.AddedAt.Local().Format("2006-01-02 15:04"), o.Meta.Size, o.Path)
			}
			var ce *vault.CorruptError
			if errors.As(err, &ce) {
				if len(opened) > 0 {
					fmt.Printf("\n無事だった %d 件を %s に取り出しました。\n", len(opened), outDir)
				}
				return fmt.Errorf("%w\n(コンテナと鍵は破棄していません)", err)
			}
			if err != nil {
				return fmt.Errorf("開封に失敗しました (コンテナと鍵は破棄していません): %w", err)
			}
			fmt.Printf("\n%d 件を %s に展開しました。\n", len(opened), outDir)

			if !destroy {
				fmt.Println("コンテナと秘密鍵はそのまま残っています (--and-destroy-key で破棄)。")
				return nil
			}
			targets := append([]string{containerPath}, keyPaths...)
			if fileExists(timelockPath()) && !slices.Contains(targets, timelockPath()) {
				targets = append(targets, timelockPath())
			}
			fmt.Printf("\n%s を上書き消去します。元には戻せません。\n", strings.Join(targets, ", "))
			if !confirm("本当に破棄しますか？") {
				fmt.Println("破棄を中止しました。")
				return nil
			}
			for _, p := range targets {
				if err := vault.Shred(p); err != nil {
					return fmt.Errorf("%s の破棄に失敗: %w", p, err)
				}
			}
			os.Remove(pubkeyPath())
			fmt.Println("破棄しました。カプセルは壊れました。")
			fmt.Println("(開封に使わなかった鍵の欠片が他の場所にあれば、もう役目はないので捨ててかまいません)")
			return nil
		},
	}
	c.Flags().StringArrayVar(&keyPaths, "key", nil, "秘密鍵・鍵の欠片・タイムロック鍵のファイル (欠片は繰り返して必要数ぶん指定。省略時は <コンテナ>.tlock)")
	c.Flags().StringVar(&outDir, "out", "", "展開先ディレクトリ (既定: ./vault-opened-<日時>/)")
	c.Flags().BoolVar(&destroy, "and-destroy-key", false, "展開後にコンテナと秘密鍵を上書き消去する (確認あり)")
	return c
}

func splitCmd() *cobra.Command {
	var keyPath, keyOut string
	var threshold, shares int
	var deleteOriginal bool
	c := &cobra.Command{
		Use:   "split",
		Short: "既存の秘密鍵を K-of-N の欠片に分割する",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if threshold < 2 {
				return errors.New("--threshold は 2 以上を指定してください")
			}
			id, err := vault.LoadIdentity(keyPath)
			if err != nil {
				return err
			}
			if keyOut == "" {
				keyOut = keyPath
			}
			files, err := vault.WriteKeys(id, keyOut, threshold, shares)
			if err != nil {
				return err
			}
			printShares(files, threshold, shares, false)
			if !deleteOriginal {
				fmt.Printf("\n元の秘密鍵 %s はそのまま残っています。欠片の保管が済んだら消去してください (--delete-original)。\n", keyPath)
				return nil
			}
			fmt.Printf("\n元の秘密鍵 %s を上書き消去します。以後は欠片でしか開封できません。\n", keyPath)
			if !confirm("本当に消去しますか？") {
				fmt.Println("消去を中止しました。")
				return nil
			}
			if err := vault.Shred(keyPath); err != nil {
				return err
			}
			fmt.Println("元の秘密鍵を消去しました。")
			return nil
		},
	}
	c.Flags().StringVar(&keyPath, "key", "", "分割する秘密鍵ファイル (必須)")
	c.Flags().StringVar(&keyOut, "key-out", "", "欠片ファイル名の元 (既定: --key と同じ)")
	c.Flags().BoolVar(&deleteOriginal, "delete-original", false, "分割後に元の秘密鍵を上書き消去する (確認あり)")
	addSplitFlags(c, &threshold, &shares)
	c.MarkFlagRequired("key")
	c.MarkFlagRequired("shares")
	c.MarkFlagRequired("threshold")
	return c
}

// parseSize は "500M" "1G" "65536" のような表記をバイト数に変換する (1K = 1024)。
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimSuffix(strings.TrimSuffix(s, "B"), "I")
	mult := int64(1)
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		}
		if mult > 1 {
			s = s[:n-1]
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("サイズの形式が不正です: %q", s)
	}
	return v * mult, nil
}
