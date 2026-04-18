package pedersen

import (
	"crypto/sha256"
	"github.com/btcsuite/btcd/btcec/v2"
	"math/big"
)

// Point represents a point on an elliptic curve
type Point struct {
	X, Y *big.Int
}

// Params holds the public parameters for Pedersen commitments.
// G is the base generator, H is a second generator where log_G(H) is unknown.
type Params struct {
	G *Point
	H *Point
}

// Commitment represents a Pedersen commitment C = v*G + r*H
type Commitment struct {
	Point *Point
}

// Opening contains the value and blinding factor needed to open a commitment
type Opening struct {
	Value    *big.Int
	Blinding *big.Int
}

type Pedersen interface {
	// Setup generates the public parameters (G, H) for the commitment scheme.
	// H is derived so that the discrete log relationship between G and H is unknown.
	Setup(seed []byte) (*Params, error)

	// Commit creates a Pedersen commitment C = v*G + r*H
	// where v is the value and r is the blinding factor.
	// Returns the commitment and the opening (value + blinding factor).
	Commit(params *Params, value *big.Int, blinding []byte) (*Commitment, *Opening, error)

	// Verify checks that a commitment matches a given opening.
	// Recomputes C' = v*G + r*H and checks C' == C.
	Verify(params *Params, commitment *Commitment, opening *Opening) bool
}

type Impl struct {
}

func Setup(seed []byte) (*Params, error) {
	curve := btcec.S256()
	Gx := curve.Params().Gx
	Gy := curve.Params().Gy

	hCurve := btcec.S256()
	h := sha256.New()
	h.Write(seed)
	hBytes := h.Sum(nil) // 32-byte hash

	hScalar := new(big.Int).SetBytes(hBytes)
	hScalar.Mod(hScalar, hCurve.Params().N)

	Hx, Hy := hCurve.ScalarBaseMult(hScalar.Bytes())

	return &Params{
		G: &Point{
			X: Gx,
			Y: Gy,
		},
		H: &Point{
			X: Hx,
			Y: Hy,
		},
	}, nil
}
