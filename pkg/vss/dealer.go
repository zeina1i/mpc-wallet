package vss

import (
	"math/big"

	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

type Dealer struct {
	shamir []*shamir.Share
}

func (d Dealer) NewDealer(secret *big.Int, threshold, total int) (Dealer, error) {
	sh, _ := shamir.Split(secret, shamir.Secp256k1Order(), threshold, total)

	return Dealer{
		shamir: sh,
	}, nil
}
