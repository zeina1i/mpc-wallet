package vss

import (
	"crypto/elliptic"
	"math/big"
)

// PointOperations provides operations on elliptic curve points
type PointOperations interface {
	// ScalarBaseMult computes k·G where G is generator
	// curve: elliptic curve
	// k: scalar value
	// Returns: point k·G
	ScalarBaseMult(curve elliptic.Curve, k *big.Int) (*Point, error)

	// ScalarMult computes k·P
	// curve: elliptic curve
	// point: point P
	// k: scalar value
	// Returns: point k·P
	ScalarMult(curve elliptic.Curve, point *Point, k *big.Int) (*Point, error)

	// Add adds two points P + Q
	// curve: elliptic curve
	// p1: first point
	// p2: second point
	// Returns: point P + Q
	Add(curve elliptic.Curve, p1, p2 *Point) (*Point, error)

	// Equal checks if two points are equal
	// p1: first point
	// p2: second point
	// Returns: true if equal, false otherwise
	Equal(p1, p2 *Point) bool

	// IsOnCurve checks if point is on curve
	// curve: elliptic curve
	// point: point to check
	// Returns: true if on curve, false otherwise
	IsOnCurve(curve elliptic.Curve, point *Point) bool

	// IsIdentity checks if point is identity (point at infinity)
	// point: point to check
	// Returns: true if identity, false otherwise
	IsIdentity(point *Point) bool
}

// NewPointOperations creates point operations handler
// Returns: PointOperations instance
//func NewPointOperations() PointOperations
