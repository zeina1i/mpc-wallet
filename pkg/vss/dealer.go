package vss

import (
	"crypto/rand"
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

	// Generate blinding polynomial g(x) with random coefficients r₀…r_{t-1}
	blindingCoeffs := make([]*big.Int, threshold)
	for i := range blindingCoeffs {
		r, err := rand.Int(rand.Reader, params.N)
		if err != nil {
			return nil, err
		}
		blindingCoeffs[i] = r
	}

	// Compute commitments directly: Cᵢ = aᵢ·G + rᵢ·H (on params.Curve)
	curve := params.Curve
	commitments := make([]*Commitment, threshold)
	for i := 0; i < threshold; i++ {
		aGx, aGy := curve.ScalarBaseMult(coefficients[i].Bytes())
		rHx, rHy := curve.ScalarMult(params.H.X, params.H.Y, blindingCoeffs[i].Bytes())
		cx, cy := curve.Add(aGx, aGy, rHx, rHy)
		commitments[i] = &Commitment{C: &Point{X: cx, Y: cy}}
	}

	// TODO: evaluate the polynomial f(i) for each participant i = 1 … total.
	// share_i = f(i) mod N  →  Store as &Share{Index: i, Value: f(i)}
	// Hint: f(i) = a₀ + a₁·i + a₂·i² + … + a_{t-1}·i^{t-1}  (all mod params.N)
	// Horner's method is a clean way to evaluate: f(x) = a₀ + x·(a₁ + x·(a₂ + …))
	// Evaluate f(i) and g(i) for each participant
	shares := make([]*Share, total)
	for i := 1; i <= total; i++ {
		x := big.NewInt(int64(i))

		// g(i) = r₀ + r₁·i + … + r_{t-1}·i^{t-1} mod N
		gi := new(big.Int)
		power := big.NewInt(1)
		for _, r := range blindingCoeffs {
			term := new(big.Int).Mul(r, power)
			gi.Add(gi, term)
			power.Mul(power, x)
			power.Mod(power, params.N)
		}
		gi.Mod(gi, params.N)

		shares[i-1] = &Share{
			Index:         i,
			Value:         poly.EvaluateAt(x),
			BlindingValue: gi,
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
	if index < 1 || index > d.total {
		return nil, ErrInvalidShareIndex
	}
	return d.shares[index-1], nil
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
