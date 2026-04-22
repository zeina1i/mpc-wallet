package vss

import (
	"crypto/rand"
	"github.com/zeina1i/mpc-wallet/pkg/pedersen"
	"math/big"

	"github.com/zeina1i/mpc-wallet/pkg/shamir"
)

type Dealer struct {
	params      *pedersen.Params
	fShares     []*shamir.Share
	gShares     []*shamir.Share
	commitments []*pedersen.Commitment
}

func NewDealer(secret *big.Int, threshold, total int, seed []byte) (Dealer, error) {
	N := shamir.Secp256k1Order()

	params, err := pedersen.Setup(seed)
	if err != nil {
		return Dealer{}, err
	}

	fPoly, err := shamir.NewPolynomial(secret, N, threshold)
	if err != nil {
		return Dealer{}, err
	}

	gSecret, err := rand.Int(rand.Reader, N)
	if err != nil {
		return Dealer{}, err
	}

	gPoly, err := shamir.NewPolynomial(gSecret, N, threshold)
	if err != nil {
		return Dealer{}, err
	}

	fShares := make([]*shamir.Share, total)
	gShares := make([]*shamir.Share, total)
	for i := 1; i <= total; i++ {
		x := big.NewInt(int64(i))
		fShares[i-1] = &shamir.Share{Index: i, Value: fPoly.EvaluateAt(x)}
		gShares[i-1] = &shamir.Share{Index: i, Value: gPoly.EvaluateAt(x)}
	}

	cms, _, err := pedersen.CommitCoefficients(params, fPoly.GetCoefficients(), gPoly.GetCoefficients())
	if err != nil {
		return Dealer{}, err
	}

	return Dealer{
		params:      params,
		fShares:     fShares,
		gShares:     gShares,
		commitments: cms,
	}, nil

}

func (d Dealer) Shares() []*shamir.Share             { return d.fShares }
func (d Dealer) BlindingShares() []*shamir.Share     { return d.gShares }
func (d Dealer) Commitments() []*pedersen.Commitment { return d.commitments }
func (d Dealer) Params() *pedersen.Params            { return d.params }
