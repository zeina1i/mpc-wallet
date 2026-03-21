package vss

import "math/big"

// Polynomial represents a polynomial f(x) = a₀ + a₁x + a₂x² + ...
type Polynomial interface {
	// Evaluate computes f(x) for given x
	// x: point to evaluate at
	// modulus: field modulus for arithmetic
	// Returns: f(x) mod modulus
	Evaluate(x *big.Int, modulus *big.Int) *big.Int

	// GetCoefficients returns polynomial coefficients
	// Returns: [a₀, a₁, a₂, ...]
	GetCoefficients() []*big.Int

	// GetDegree returns polynomial degree
	// Returns: len(coefficients) - 1
	GetDegree() int

	// GetConstantTerm returns a₀ (the secret)
	GetConstantTerm() *big.Int
}

// NewPolynomial creates polynomial from coefficients
// coefficients: [a₀, a₁, a₂, ...] where a₀ is secret
// Returns: Polynomial instance
//func NewPolynomial(coefficients []*big.Int) Polynomial

// NewRandomPolynomial creates polynomial with random coefficients
// secret: the secret (becomes a₀)
// degree: polynomial degree (threshold - 1)
// modulus: field modulus
// Returns: Polynomial with secret as a₀, random other coefficients
//func NewRandomPolynomial(secret *big.Int, degree int, modulus *big.Int) (Polynomial, error)
