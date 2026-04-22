package vss_test

import (
	"math/big"
	"testing"

	"github.com/zeina1i/mpc-wallet/pkg/vss"
)

func TestPedersenVSS_AllSharesVerify(t *testing.T) {
	secret := big.NewInt(12345)
	seed := []byte("test-seed")

	dealer, err := vss.NewDealer(secret, 3, 5, seed)
	if err != nil {
		t.Fatalf("NewDealer: %v", err)
	}

	fShares := dealer.Shares()
	gShares := dealer.BlindingShares()
	cms := dealer.Commitments()
	params := dealer.Params()

	for i, fs := range fShares {
		gs := gShares[i]
		if !vss.VerifyShare(params, fs.Value, gs.Value, fs.Index, cms) {
			t.Errorf("share %d failed Pedersen verification", fs.Index)
		}
	}
}

func TestPedersenVSS_TamperedShareFails(t *testing.T) {
	secret := big.NewInt(99999)
	seed := []byte("tamper-test-seed")

	dealer, err := vss.NewDealer(secret, 2, 3, seed)
	if err != nil {
		t.Fatalf("NewDealer: %v", err)
	}

	fShares := dealer.Shares()
	gShares := dealer.BlindingShares()
	cms := dealer.Commitments()
	params := dealer.Params()

	// tamper with share 0's f value
	tampered := new(big.Int).Add(fShares[0].Value, big.NewInt(1))
	if vss.VerifyShare(params, tampered, gShares[0].Value, fShares[0].Index, cms) {
		t.Error("verification should fail for a tampered f-share")
	}
}

func TestPedersenVSS_CombineRecoversSecret(t *testing.T) {
	secret := big.NewInt(42)
	seed := []byte("combine-test-seed")

	dealer, err := vss.NewDealer(secret, 3, 5, seed)
	if err != nil {
		t.Fatalf("NewDealer: %v", err)
	}

	// use exactly threshold shares
	recovered, err := vss.Combine(dealer.Shares()[:3])
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if recovered.Cmp(secret) != 0 {
		t.Fatalf("want %v, got %v", secret, recovered)
	}
}
