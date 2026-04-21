package pedersen

import (
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
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
	Commit(params *Params, value *big.Int, blinding *big.Int) (*Commitment, *Opening, error)

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

	//todo: check this func
	Hx, Hy := hashToCurvePoint(hCurve, hBytes)

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

func Commit(params *Params, value *big.Int, blinding *big.Int) (*Commitment, *Opening, error) {
	//curve := btcec.S256()
	//fx, fy := curve.ScalarMult(params.G.X, params.G.Y, value.Bytes())
	//
	//curve2 := btcec.S256()
	//gx, gy := curve2.ScalarMult(params.H.X, params.H.Y, blinding.Bytes())
	curve := btcec.S256()
	n := curve.Params().N
	//todo: checkkk
	v := new(big.Int).Mod(value, n)
	r := new(big.Int).Mod(blinding, n)
	vGx, vGy := curve.ScalarMult(params.G.X, params.G.Y, v.Bytes())
	rHx, rHy := curve.ScalarMult(params.H.X, params.H.Y, r.Bytes())

	cmX, cmY := curve.Add(vGx, vGy, rHx, rHy)

	commitment := &Commitment{Point: &Point{
		X: cmX,
		Y: cmY,
	},
	}
	opening := &Opening{
		Value:    value,
		Blinding: blinding,
	}

	return commitment, opening, nil
}

func CommitCoefficients(params *Params, fCoeffs []*big.Int, gCoeffs []*big.Int) ([]*Commitment, []*Opening, error) {
	cms := make([]*Commitment, len(fCoeffs))
	ops := make([]*Opening, len(fCoeffs))

	for i := 0; i < len(fCoeffs); i++ {
		cm, opening, err := Commit(params, fCoeffs[i], gCoeffs[i])
		if err != nil {
			return nil, nil, err
		}
		cms[i] = cm
		ops[i] = opening
	}

	return cms, ops, nil
}

func Verify(params *Params, commitment *Commitment, opening *Opening) bool {
	curve := btcec.S256()
	n := curve.Params().N
	v := new(big.Int).Mod(opening.Value, n)
	r := new(big.Int).Mod(opening.Blinding, n)

	vGx, vGy := curve.ScalarMult(params.G.X, params.G.Y, v.Bytes())
	rHx, rHy := curve.ScalarMult(params.H.X, params.H.Y, r.Bytes())

	cmX, cmY := curve.Add(vGx, vGy, rHx, rHy)

	return commitment.Point.X.Cmp(cmX) == 0 && commitment.Point.Y.Cmp(cmY) == 0

}

// VerifyShare checks that a participant's share pair (fi, gi) is consistent
// with the dealer's published commitments.
//
//	LHS = fi*G + gi*H
//	RHS = Σ idx^k * C[k]  for k = 0..t-1
func VerifyShare(params *Params, fi, gi *big.Int, idx int, commitments []*Commitment) bool {
	curve := btcec.S256()
	N := curve.Params().N

	// LHS = fi*G + gi*H
	vGx, vGy := curve.ScalarMult(params.G.X, params.G.Y, fi.Bytes())
	rHx, rHy := curve.ScalarMult(params.H.X, params.H.Y, gi.Bytes())
	lhsX, lhsY := curve.Add(vGx, vGy, rHx, rHy)

	// RHS = Σ idx^k * C[k]
	index := big.NewInt(int64(idx))
	iPow := big.NewInt(1)

	var rhsX, rhsY *big.Int
	for k, c := range commitments {
		scalar := new(big.Int).Mod(iPow, N)
		termX, termY := curve.ScalarMult(c.Point.X, c.Point.Y, scalar.Bytes())

		if k == 0 {
			rhsX, rhsY = termX, termY
		} else {
			rhsX, rhsY = curve.Add(rhsX, rhsY, termX, termY)
		}

		iPow.Mul(iPow, index)
		iPow.Mod(iPow, N)
	}

	return lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0
}

func hashToCurvePoint(curve *btcec.KoblitzCurve, seed []byte) (*big.Int, *big.Int) {
	for i := 0; ; i++ {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{byte(i)})
		digest := h.Sum(nil)
		x := new(big.Int).SetBytes(digest)
		x.Mod(x, curve.Params().P)
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		ax := new(big.Int).Mul(curve.Params().B, big.NewInt(0)) // a=0 for secp256k1
		rhs := new(big.Int).Add(x3, ax)
		rhs.Add(rhs, curve.Params().B)
		rhs.Mod(rhs, curve.Params().P)
		y := new(big.Int).ModSqrt(rhs, curve.Params().P)
		if y != nil && curve.IsOnCurve(x, y) {
			return x, y
		}
	}
}
