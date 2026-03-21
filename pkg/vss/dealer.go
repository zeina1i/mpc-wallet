package vss

import "math/big"

// Dealer manages VSS share creation and distribution
type Dealer interface {
	// GetCommitments returns commitments to broadcast publicly
	// These allow verifiers to check their shares
	// Returns: [C₀, C₁, C₂, ...] where Cᵢ = aᵢ·G
	GetCommitments() []*Commitment

	// GetShareForParticipant returns share for given participant
	// index: participant identifier (1, 2, 3, ..., total)
	// Returns: share for that participant, or error if invalid index
	GetShareForParticipant(index int) (*Share, error)

	// GetPublicKey derives public key from the secret
	// Returns: C₀ = a₀·G where a₀ is the secret
	GetPublicKey() *PublicKey

	// GetShares returns all generated shares
	// Returns: array of all shares [share₁, share₂, ..., shareₙ]
	GetShares() []*Share

	// GetSecret returns the secret (for testing only!)
	// WARNING: In production, dealer should delete this after setup
	GetSecret() *big.Int

	// GetThreshold returns the threshold value
	GetThreshold() int

	// GetTotal returns total number of shares
	GetTotal() int
}

// NewDealer creates a new VSS dealer
// params: cryptographic parameters (G, H, Curve, N)
// secret: the value to share (becomes a₀ in polynomial)
// threshold: minimum shares needed to reconstruct (t)
// total: total number of shares to create (n)
// Returns: Dealer instance or error
//func NewDealer(params *Params, secret *big.Int, threshold, total int) (Dealer, error)
