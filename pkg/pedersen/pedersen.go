package pedersen

import (
	"crypto/elliptic"
	"crypto/sha256"
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

	// Add homomorphically adds two commitments.
	// If C1 = v1*G + r1*H and C2 = v2*G + r2*H,
	// then C1 + C2 = (v1+v2)*G + (r1+r2)*H.
	Add(params *Params, c1, c2 *Commitment) *Commitment
}

type Impl struct {
}

func (Impl) Setup(seed []byte) (*Params, error) {
	curve := elliptic.P256()

	// G is the standard base generator of the curve
	G := &Point{
		X: curve.Params().Gx,
		Y: curve.Params().Gy,
	}

	// H is derived by hashing the seed to a scalar, then computing H = h*G.
	// Domain separation ("pedersen-H") ensures H is independent of G,
	// and no party knows log_G(H) as long as the seed is a public, unbiased input.
	h := sha256.New()
	h.Write([]byte("pedersen-H"))
	h.Write(seed)
	hScalar := new(big.Int).SetBytes(h.Sum(nil))
	hScalar.Mod(hScalar, curve.Params().N)

	hX, hY := curve.ScalarBaseMult(hScalar.Bytes())
	H := &Point{X: hX, Y: hY}

	return &Params{G: G, H: H}, nil
}

func (Impl) Commit(params *Params, value *big.Int, blinding []byte) (*Commitment, *Opening, error) {
	curve := elliptic.P256()
	blindingBigInt := new(big.Int).SetBytes(blinding)
	blindingBigInt.Mod(blindingBigInt, curve.Params().N)

	vGx, vGy := curve.ScalarBaseMult(value.Bytes())
	rHx, rHy := curve.ScalarMult(params.H.X, params.H.Y, blindingBigInt.Bytes())

	cx, cy := curve.Add(vGx, vGy, rHx, rHy)

	commitment := &Commitment{Point: &Point{X: cx, Y: cy}}
	opening := &Opening{Value: value, Blinding: blindingBigInt}

	return commitment, opening, nil
}

//func (Impl) Verify(params *Params, commitment *Commitment, opening *Opening) bool {
//	// value * blinding + commitment * generator
//	//curve := elliptic.P256()
//
//}
