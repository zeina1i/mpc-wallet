package vss

import (
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
	"math/big"
)

func Combine(shares []*shamir.Share) (*big.Int, error) {
	return shamir.Combine(shares, shamir.Secp256k1Order())
}
