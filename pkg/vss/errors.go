package vss

import "errors"

var (
	// Parameter errors
	ErrNilParams        = errors.New("params cannot be nil")
	ErrNilSecret        = errors.New("secret cannot be nil")
	ErrInvalidThreshold = errors.New("threshold must be >= 1 and <= total")
	ErrInvalidTotal     = errors.New("total must be >= threshold")

	// Commitment errors
	ErrNilCommitments     = errors.New("commitments cannot be nil")
	ErrEmptyCommitments   = errors.New("commitments array is empty")
	ErrInvalidCommitment  = errors.New("commitment is not a valid curve point")
	ErrCommitmentMismatch = errors.New("number of commitments doesn't match threshold")

	// Share errors
	ErrNilShare           = errors.New("share cannot be nil")
	ErrInvalidShareIndex  = errors.New("share index must be > 0 and <= total")
	ErrInvalidShareValue  = errors.New("share value is invalid")
	ErrInvalidShare       = errors.New("share verification failed")
	ErrInsufficientShares = errors.New("insufficient shares for reconstruction")
	ErrDuplicateIndex     = errors.New("duplicate share index detected")

	// Curve errors
	ErrPointNotOnCurve = errors.New("point is not on curve")
	ErrInvalidPoint    = errors.New("invalid point coordinates")

	// Serialization errors
	ErrInvalidData  = errors.New("invalid serialized data")
	ErrDataTooShort = errors.New("data too short")
)
