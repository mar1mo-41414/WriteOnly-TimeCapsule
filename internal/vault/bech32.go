package vault

// BIP-173 の bech32 エンコード。age の鍵文字列 (AGE-SECRET-KEY-1...) と
// 鍵の欠片 (WOTC-SHARE-1...) の読み書きに使う。age 本体の実装は internal
// パッケージで import できないため、仕様どおりに最小限を実装している。
// age と同じく 90 文字の長さ制限は設けない。

import (
	"errors"
	"strings"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if (top>>i)&1 == 1 {
				chk ^= bech32Gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := range len(hrp) {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := range len(hrp) {
		out = append(out, hrp[i]&31)
	}
	return out
}

func convertBits(data []byte, from, to uint32, pad bool) ([]byte, error) {
	var acc, bits uint32
	maxv := uint32(1)<<to - 1
	var out []byte
	for _, b := range data {
		if uint32(b)>>from != 0 {
			return nil, errors.New("bech32: 不正な値")
		}
		acc = acc<<from | uint32(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("bech32: 不正なパディング")
	}
	return out, nil
}

// bech32Encode は hrp と data を小文字の bech32 文字列にする。
func bech32Encode(hrp string, data []byte) (string, error) {
	hrp = strings.ToLower(hrp)
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	chkIn := append(bech32HRPExpand(hrp), values...)
	chkIn = append(chkIn, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(chkIn) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range values {
		sb.WriteByte(bech32Charset[v])
	}
	for i := range 6 {
		sb.WriteByte(bech32Charset[(mod>>(5*(5-i)))&31])
	}
	return sb.String(), nil
}

// bech32Decode は bech32 文字列を hrp (小文字) と data に分解し、チェックサムを検証する。
func bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32: 大文字と小文字が混在しています")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bech32: 形式が不正です")
	}
	hrp := s[:pos]
	values := make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		v := strings.IndexByte(bech32Charset, s[i])
		if v < 0 {
			return "", nil, errors.New("bech32: 使えない文字が含まれています")
		}
		values = append(values, byte(v))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("bech32: チェックサム不一致 (書き写し間違い?)")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}
