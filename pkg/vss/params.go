package vss

import (
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// NewParamsSecp256k1 creates Params for the secp256k1 curve.
// G is the standard generator. H is derived via SHA256 so no one knows log_G(H).
func NewParamsSecp256k1() *Params {
	curve := btcec.S256()

	G := &Point{X: curve.Params().Gx, Y: curve.Params().Gy}

	h := sha256.New()
	h.Write([]byte("pedersen-H"))
	h.Write([]byte("secp256k1"))
	hScalar := new(big.Int).SetBytes(h.Sum(nil))
	hScalar.Mod(hScalar, curve.Params().N)
	hX, hY := curve.ScalarBaseMult(hScalar.Bytes())

	return &Params{
		G:     G,
		H:     &Point{X: hX, Y: hY},
		Curve: curve,
		N:     curve.Params().N,
	}
}
