package vss

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
//func NewVerifier(params *Params, commitments []*Commitment) (Verifier, error)
