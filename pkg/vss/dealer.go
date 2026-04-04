package vss

import (
	"crypto/rand"
	"github.com/zeina1i/mpc-wallet/pkg/pedersen"
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
	"math/big"
)

type dealer struct {
	params      *Params
	threshold   int
	total       int
	secret      *big.Int
	commitments []*Commitment
	shares      []*Share
	publicKey   *PublicKey
}

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
func NewDealer(params *Params, secret *big.Int, threshold, total int) (Dealer, error) {
	// TODO: validate inputs (nil params, nil secret, threshold >= 1, threshold <= total)

	// Build the polynomial f(x) = a₀ + a₁x + … + a_{t-1}x^{t-1} mod N
	// shamir.NewPolynomial sets a₀ = secret and picks a₁…a_{t-1} at random.
	poly, err := shamir.NewPolynomial(secret, params.N, threshold)
	if err != nil {
		return nil, err
	}
	coefficients := poly.GetCoefficients() // [a₀, a₁, …, a_{t-1}]

	pImpl := &pedersen.Impl{}

	// Pedersen VSS: commit to each coefficient — Cᵢ = aᵢ·G + rᵢ·H
	// The commitments array should have `threshold` entries, one per coefficient.
	commitments := make([]*Commitment, 0, threshold)

	// BUG: blinding must be random per commitment (fresh rand.Int each iteration).
	// Using a hardcoded value breaks the hiding property of the commitment.

	// BUG: loop should run `threshold` times (one commit per coefficient), not `total`.
	for i := 0; i < threshold; i++ {
		blinding, _ := rand.Int(rand.Reader, params.N) // fresh each iteration
		// BUG: pImpl.Commit expects *pedersen.Params, not *vss.Params.
		// You need to build a *pedersen.Params from params.G and params.H first.
		//
		// BUG: Commit returns (*pedersen.Commitment, *pedersen.Opening, error) — capture them.
		// Use the returned commitment's Point (X, Y) to fill a *vss.Commitment.
		//
		// BUG: append result is discarded — assign it back: commitments = append(...)
		ps := pedersen.Params{
			G: &pedersen.Point{X: params.G.X, Y: params.G.Y},
			H: &pedersen.Point{X: params.H.X, Y: params.H.Y},
		}
		cm, _, _ := pImpl.Commit(&ps, coefficients[i], blinding.Bytes())
		commitments = append(commitments, &Commitment{C: &Point{X: cm.Point.X, Y: cm.Point.Y}})
	}

	// TODO: evaluate the polynomial f(i) for each participant i = 1 … total.
	// share_i = f(i) mod N  →  Store as &Share{Index: i, Value: f(i)}
	// Hint: f(i) = a₀ + a₁·i + a₂·i² + … + a_{t-1}·i^{t-1}  (all mod params.N)
	// Horner's method is a clean way to evaluate: f(x) = a₀ + x·(a₁ + x·(a₂ + …))
	shares := make([]*Share, total)
	for i := 0; i < total; i++ {
		x := big.NewInt(int64(i))
		shares[i-1] = &Share{
			Index: i,
			Value: poly.EvaluateAt(x),
		}
	}

	// TODO: derive the public key — PK = secret·G
	// Use params.Curve.ScalarBaseMult(secret.Bytes()) to get (X, Y).
	// Wrap in &PublicKey{Point: &Point{X: ..., Y: ...}}
	pubX, pubY := params.Curve.ScalarBaseMult(secret.Bytes())
	publicKey := &PublicKey{
		Point: &Point{X: pubX, Y: pubY},
	}
	// TODO: define a concrete `dealer` struct that holds all the fields above
	return &dealer{
		params:      params,
		threshold:   threshold,
		total:       total,
		secret:      secret,
		commitments: commitments,
		shares:      shares,
		publicKey:   publicKey,
	}, nil
}

func (d dealer) GetCommitments() []*Commitment {
	return d.commitments
}

func (d dealer) GetShareForParticipant(index int) (*Share, error) {
	return d.shares[index], nil

}

func (d dealer) GetPublicKey() *PublicKey {
	return d.publicKey

}
func (d dealer) GetShares() []*Share {
	return d.shares

}
func (d dealer) GetSecret() *big.Int {
	return d.secret

}
func (d dealer) GetThreshold() int {
	return d.threshold

}
func (d dealer) GetTotal() int {
	return d.total
}
