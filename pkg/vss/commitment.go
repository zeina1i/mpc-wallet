package vss

import "math/big"

// CommitmentOperations provides operations on commitments
type CommitmentOperations interface {
	// CreateCommitment creates commitment to a value
	// params: cryptographic parameters
	// value: value to commit to
	// Returns: commitment (value·G)
	CreateCommitment(params *Params, value *big.Int) (*Commitment, error)

	// AddCommitments adds two commitments (homomorphic property)
	// params: cryptographic parameters
	// c1: first commitment
	// c2: second commitment
	// Returns: c1 + c2
	AddCommitments(params *Params, c1, c2 *Commitment) (*Commitment, error)

	// ScalarMultCommitment multiplies commitment by scalar
	// params: cryptographic parameters
	// commitment: commitment to multiply
	// scalar: scalar value
	// Returns: scalar·commitment
	ScalarMultCommitment(params *Params, commitment *Commitment, scalar *big.Int) (*Commitment, error)

	// ComputeSum computes weighted sum of commitments
	// Used in verification: C₀ + x·C₁ + x²·C₂ + ...
	// params: cryptographic parameters
	// commitments: array of commitments
	// x: the index (weight base)
	// Returns: C₀ + x·C₁ + x²·C₂ + ...
	ComputeSum(params *Params, commitments []*Commitment, x *big.Int) (*Point, error)
}

// NewCommitmentOperations creates commitment operations handler
// Returns: CommitmentOperations instance
//func NewCommitmentOperations() CommitmentOperations
