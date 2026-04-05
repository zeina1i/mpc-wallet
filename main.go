package main

import (
	"fmt"
	"github.com/zeina1i/mpc-wallet/pkg/vss"
	"log"
	"math/big"
)

func main() {
	// Setup
	params := vss.NewParamsSecp256k1()
	secret := big.NewInt(12345)

	// Create dealer
	dealer, err := vss.NewDealer(params, secret, 3, 5)
	if err != nil {
		log.Fatal(err)
	}

	// Get commitments
	commitments := dealer.GetCommitments()
	fmt.Printf("Commitments: %d\n", len(commitments))

	// Get public key
	pubKey := dealer.GetPublicKey()
	fmt.Printf("Public Key: %x\n", pubKey.Point.X.Bytes()[:8])

	// Create verifier
	verifier, err := vss.NewVerifier(params, commitments)
	if err != nil {
		log.Fatal(err)
	}

	// Get and verify share
	share, _ := dealer.GetShareForParticipant(1)
	valid := verifier.VerifyShare(share)
	fmt.Printf("Share valid: %v\n", valid)

	if valid {
		verifier.AcceptShare(share)
	}

	shares := dealer.GetShares()[:3]
	reconstructed, err := vss.Reconstruct(params, shares)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Reconstructed: %s\n", reconstructed)
	fmt.Printf("Matches: %v\n", reconstructed.Cmp(secret) == 0)
}
