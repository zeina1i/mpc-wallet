package vss

import (
	"github.com/zeina1i/mpc-wallet/pkg/pedersen"
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
	"math/big"
)

func VerifyShare(params *pedersen.Params, fi, gi *big.Int, idx int, commitments []*pedersen.Commitment) bool {
	return pedersen.VerifyShare(params, fi, gi, idx, commitments)
}

func Combine(shares []*shamir.Share) (*big.Int, error) {
	return shamir.Combine(shares, shamir.Secp256k1Order())
}
