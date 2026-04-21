package vss

import (
	"math/big"

	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

type Dealer struct {
	shamir []*shamir.Share
}

func NewDealer(secret *big.Int, threshold, total int) (Dealer, error) {
	sh, err := shamir.Split(secret, shamir.Secp256k1Order(), threshold, total)
	if err != nil {
		return Dealer{}, err
	}

	return Dealer{
		shamir: sh,
	}, nil
}

func (d Dealer) Shares() []*shamir.Share {
	return d.shamir
}
