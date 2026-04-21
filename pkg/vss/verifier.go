package vss

import (
	"github.com/zeina1i/mpc-wallet/pkg/shamir"
	"math/big"
)

func Combine(shares []*shamir.Share) (*big.Int, error) {
	return shamir.Combine(shares, shamir.Secp256k1Order())
}

//claude --resume ba9b974c-7526-4c91-8004-5d23a05aaaaf
