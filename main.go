package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/zeina1i/mpc-wallet/pkg/vss"
)

func main() {
	secret := big.
		NewInt(42)
	threshold := 2
	total := 3

	dealer, err := vss.NewDealer(secret, threshold, total, []byte("main-seed"))
	if err != nil {
		log.Fatalf("failed to create dealer: %v", err)
	}

	fmt.Printf("Secret split into %d shares (threshold=%d)\n", total, threshold)
	for _, s := range dealer.Shares() {
		fmt.Printf("  share[%d] = %s\n", s.Index, s.Value.String())
	}

	reconstructedSecret, _ := vss.Combine(dealer.Shares())
	fmt.Printf(reconstructedSecret.String())
}
