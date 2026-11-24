//go:build !unix

package vault

// canWrite は unix 以外では判定手段がないため true を返し、実際の操作時の
// エラーに任せる。ただし未対応 OS ではコンテナ操作自体が lockFile の時点で
// 「未対応」エラーになるため、この楽観的な判定だけで処理が進むことはない
// (判定が使われるのは破棄可否の事前確認のみ)。
func canWrite(string) bool { return true }
