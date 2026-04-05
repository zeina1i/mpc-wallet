package vss

import (
	"math/big"

	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

// Reconstruct recovers the secret from a set of shares using Lagrange interpolation.
// Requires at least threshold shares.
func Reconstruct(params *Params, shares []*Share) (*big.Int, error) {
	shamirShares := make([]*shamir.Share, len(shares))
	for i, s := range shares {
		shamirShares[i] = &shamir.Share{Index: s.Index, Value: s.Value}
	}
	return shamir.Combine(shamirShares, params.N)
}
