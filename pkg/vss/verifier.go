package vss

import "math/big"

type verfier struct {
	params      *Params
	commitments []*Commitment
	share       *Share
}

// Verifier manages share verification
type Verifier interface {
	// VerifyShare checks if share is valid against commitments
	// Uses equation: share·G = C₀ + index·C₁ + index²·C₂ + ...
	// share: the share to verify
	// Returns: true if valid, false if invalid (dealer cheating!)
	VerifyShare(share *Share) bool

	// AcceptShare stores a verified share
	// Only call after VerifyShare returns true
	// share: the share to accept
	// Returns: error if share fails verification
	AcceptShare(share *Share) error

	// GetPublicKey derives public key from commitments
	// Returns: same public key as dealer (C₀)
	GetPublicKey() *PublicKey

	// GetMyShare returns this verifier's accepted share
	// Returns: nil if no share accepted yet
	GetMyShare() *Share

	// GetCommitments returns the commitments being used
	GetCommitments() []*Commitment
}

// NewVerifier creates a new verifier
// params: cryptographic parameters (must match dealer's)
// commitments: public commitments from dealer
// Returns: Verifier instance or error
func NewVerifier(params *Params, commitments []*Commitment) (Verifier, error) {
	return &verfier{params: params, commitments: commitments}, nil
}

func (v *verfier) VerifyShare(share *Share) bool {
	//todo: transfer this logic to pedersen
	curve := v.params.Curve
	N := v.params.N
	index := big.NewInt(int64(share.Index))

	// lhs = f(i)·G + g(i)·H
	lhsX, lhsY := curve.ScalarBaseMult(share.Value.Bytes())
	rhX, rhY := curve.ScalarMult(v.params.H.X, v.params.H.Y, share.BlindingValue.Bytes())
	lhsX, lhsY = curve.Add(lhsX, lhsY, rhX, rhY)

	// rhs = C₀ + i·C₁ + i²·C₂ + …
	power := big.NewInt(1) // i^j, starts at i^0 = 1
	var rhsX, rhsY *big.Int
	for _, c := range v.commitments {
		termX, termY := curve.ScalarMult(c.C.X, c.C.Y, power.Bytes())
		if rhsX == nil {
			rhsX, rhsY = termX, termY
		} else {
			rhsX, rhsY = curve.Add(rhsX, rhsY, termX, termY)
		}
		power.Mul(power, index)
		power.Mod(power, N)
	}

	return lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0
}

func (v *verfier) AcceptShare(share *Share) error {
	if !v.VerifyShare(share) {
		return ErrInvalidShare
	}
	v.share = share
	return nil
}

func (v *verfier) GetPublicKey() *PublicKey {
	return &PublicKey{Point: v.commitments[0].C}
}

func (v *verfier) GetMyShare() *Share {
	return v.share
}

func (v *verfier) GetCommitments() []*Commitment {
	return v.commitments
}
