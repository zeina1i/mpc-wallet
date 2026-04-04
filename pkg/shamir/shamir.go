// Package shamir implements Shamir Secret Sharing over a prime field Z_p.
//
// Unlike GF(256)-based implementations, this works directly with big.Int
// arithmetic mod a prime modulus — compatible with elliptic curve scalar fields
// such as secp256k1 (used by Ethereum and Bitcoin).
//
// The scheme:
//   - Dealer builds a polynomial f(x) = a₀ + a₁x + … + a_{t-1}x^{t-1}  mod N
//     where a₀ = secret and a₁…a_{t-1} are random
//   - Share i  =  f(i)  for i = 1 … n
//   - Any t shares reconstruct f(0) = secret via Lagrange interpolation
//   - Any t-1 shares reveal nothing about the secret (information-theoretic)
package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// ============= ERRORS =============

var (
	ErrInvalidThreshold   = errors.New("threshold must be >= 1 and <= total")
	ErrInvalidTotal       = errors.New("total must be >= threshold")
	ErrInsufficientShares = errors.New("insufficient shares for reconstruction")
	ErrNilSecret          = errors.New("secret cannot be nil")
	ErrNilModulus         = errors.New("modulus cannot be nil")
	ErrDuplicateIndex     = errors.New("duplicate share indices detected")
	ErrInvalidShareIndex  = errors.New("share index must be > 0")
	ErrNilShare           = errors.New("share cannot be nil")
)

// ============= TYPES =============

// Share is a single participant's share: the value f(Index) mod N.
type Share struct {
	Index int      // participant identifier (1, 2, 3, …)
	Value *big.Int // f(Index) mod N
}

// Polynomial is f(x) = a₀ + a₁x + … + a_{t-1}x^{t-1}  mod modulus.
// a₀ is the secret; all arithmetic is mod modulus (typically the curve order N).
type Polynomial struct {
	coefficients []*big.Int // [a₀, a₁, …, a_{t-1}]
	modulus      *big.Int   // prime modulus
}

// ============= POLYNOMIAL =============

// NewPolynomial builds a degree-(threshold-1) polynomial with secret as the
// constant term and random coefficients for the remaining terms.
func NewPolynomial(secret, modulus *big.Int, threshold int) (*Polynomial, error) {
	if secret == nil {
		return nil, ErrNilSecret
	}
	if modulus == nil {
		return nil, ErrNilModulus
	}
	if threshold < 1 {
		return nil, ErrInvalidThreshold
	}

	coefficients := make([]*big.Int, threshold)
	coefficients[0] = new(big.Int).Mod(secret, modulus) // a₀ = secret

	for i := 1; i < threshold; i++ {
		c, err := rand.Int(rand.Reader, modulus)
		if err != nil {
			return nil, fmt.Errorf("generating random coefficient: %w", err)
		}
		coefficients[i] = c
	}

	return &Polynomial{coefficients: coefficients, modulus: modulus}, nil
}

// EvaluateAt computes f(x) mod modulus using Horner's method.
// Horner: f(x) = a₀ + x·(a₁ + x·(a₂ + … + x·a_{t-1}))
// This avoids computing powers of x explicitly and is more efficient.
func (p *Polynomial) EvaluateAt(x *big.Int) *big.Int {
	result := new(big.Int).Set(p.coefficients[len(p.coefficients)-1])

	for i := len(p.coefficients) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, p.coefficients[i])
		result.Mod(result, p.modulus)
	}

	return result
}

// GetCoefficients returns a copy of [a₀, a₁, …, a_{t-1}].
// The dealer needs these to create the Pedersen/Feldman commitments.
func (p *Polynomial) GetCoefficients() []*big.Int {
	out := make([]*big.Int, len(p.coefficients))
	for i, c := range p.coefficients {
		out[i] = new(big.Int).Set(c)
	}
	return out
}

// GetDegree returns threshold - 1.
func (p *Polynomial) GetDegree() int { return len(p.coefficients) - 1 }

// GetSecret returns a copy of a₀ (the secret / constant term).
func (p *Polynomial) GetSecret() *big.Int { return new(big.Int).Set(p.coefficients[0]) }

// ============= SPLIT / COMBINE =============

// Split creates n shares of secret with a t-of-n threshold, all mod modulus.
// Returns shares [f(1), f(2), …, f(n)].
func Split(secret, modulus *big.Int, threshold, total int) ([]*Share, error) {
	if threshold < 1 || threshold > total {
		return nil, ErrInvalidThreshold
	}

	poly, err := NewPolynomial(secret, modulus, threshold)
	if err != nil {
		return nil, err
	}

	shares := make([]*Share, total)
	for i := 1; i <= total; i++ {
		x := big.NewInt(int64(i))
		shares[i-1] = &Share{
			Index: i,
			Value: poly.EvaluateAt(x),
		}
	}

	return shares, nil
}

// Combine reconstructs the secret from at least threshold shares using
// Lagrange interpolation at x = 0:
//
//	secret = Σᵢ  yᵢ · Π_{j≠i} ( -xⱼ / (xᵢ - xⱼ) )  mod modulus
func Combine(shares []*Share, modulus *big.Int) (*big.Int, error) {
	if err := validateShares(shares); err != nil {
		return nil, err
	}

	secret := new(big.Int)

	for i, si := range shares {
		xi := big.NewInt(int64(si.Index))

		num := big.NewInt(1) // numerator   of the i-th Lagrange basis
		den := big.NewInt(1) // denominator of the i-th Lagrange basis

		for j, sj := range shares {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(sj.Index))

			// num *= -xj  (mod modulus)
			num.Mul(num, new(big.Int).Neg(xj))
			num.Mod(num, modulus)

			// den *= (xi - xj)  (mod modulus)
			diff := new(big.Int).Sub(xi, xj)
			den.Mul(den, diff)
			den.Mod(den, modulus)
		}

		// lagrange_i = num * den⁻¹  mod modulus
		denInv := new(big.Int).ModInverse(den, modulus)
		lagrange := new(big.Int).Mul(num, denInv)
		lagrange.Mod(lagrange, modulus)

		// secret += y_i * lagrange_i
		term := new(big.Int).Mul(si.Value, lagrange)
		secret.Add(secret, term)
		secret.Mod(secret, modulus)
	}

	return secret, nil
}

// ============= SECP256K1 HELPERS =============

// Secp256k1Order returns the order N of the secp256k1 curve used by Ethereum.
// Use this as the modulus for Split/Combine/NewPolynomial in Ethereum contexts.
func Secp256k1Order() *big.Int {
	return btcec.S256().N
}

// ============= VALIDATION =============

func validateShares(shares []*Share) error {
	if len(shares) == 0 {
		return ErrInsufficientShares
	}

	seen := make(map[int]bool, len(shares))
	for _, s := range shares {
		if s == nil {
			return ErrNilShare
		}
		if s.Index <= 0 {
			return ErrInvalidShareIndex
		}
		if seen[s.Index] {
			return fmt.Errorf("%w: index %d", ErrDuplicateIndex, s.Index)
		}
		seen[s.Index] = true
	}

	return nil
}
