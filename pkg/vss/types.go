package vss

import (
	"crypto/elliptic"
	"math/big"
)

// ============= CORE TYPES =============

// Params holds cryptographic parameters for VSS operations
type Params struct {
	G     *Point         // First generator point
	H     *Point         // Second generator point (nil for Feldman VSS)
	Curve elliptic.Curve // The elliptic curve
	N     *big.Int       // Curve order (for modular arithmetic)
}

// Point represents a point on an elliptic curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// Commitment represents a commitment to a polynomial coefficient
type Commitment struct {
	C *Point // Commitment point (Cᵢ = aᵢ·G)
}

// Share represents a single VSS share
type Share struct {
	Index         int      // Participant index (1, 2, 3, ...)
	Value         *big.Int // Share value f(index)
	BlindingValue *big.Int
}

// PublicKey represents the derived public key
type PublicKey struct {
	Point *Point // Public key point (C₀ = secret·G)
}

type Opening struct {
	Value    *big.Int
	Blinding *big.Int
}
