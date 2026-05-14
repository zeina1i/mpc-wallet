package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zeina1i/mpc-wallet/pkg/wallet"
)

const (
	parties   = 3
	threshold = 1 // threshold+1 = 2 signers required
	rpcURL    = "https://ethereum-sepolia-rpc.publicnode.com"
	keysFile  = "keys.json" // persisted key shares
)

func main() {
	w, err := loadOrCreate()
	if err != nil {
		log.Fatalf("wallet: %v", err)
	}
	fmt.Printf("Wallet address: %s\n\n", w.Address().Hex())

	// --- Send Transaction ---
	// Any 2 of the 3 parties collaborate to sign without any single party
	// ever holding the full private key.
	recipient := common.HexToAddress("0x079E7DB2642B3143CE43E0C563b17e58B724c3B6")
	amount := big.NewInt(1000) // 1000 wei

	fmt.Printf("Signing and sending %s wei to %s...\n", amount, recipient.Hex())
	tx, err := w.SendTransaction(context.Background(), recipient, amount)
	if err != nil {
		log.Fatalf("send transaction: %v", err)
	}

	fmt.Printf("Transaction sent!\n")
	fmt.Printf("  Hash:     %s\n", tx.Hash().Hex())
	fmt.Printf("  Nonce:    %d\n", tx.Nonce())
	fmt.Printf("  Gas:      %d\n", tx.Gas())
	fmt.Printf("  GasPrice: %s gwei\n", new(big.Int).Div(tx.GasPrice(), big.NewInt(1e9)))
}

// loadOrCreate loads key shares from disk if keys.json exists,
// otherwise runs keygen, prints the address, and saves the shares.
func loadOrCreate() (*wallet.Wallet, error) {
	if _, err := os.Stat(keysFile); err == nil {
		fmt.Println("Loading existing key shares from", keysFile)
		return wallet.Load(keysFile, rpcURL, threshold)
	}

	fmt.Println("No key shares found — running MPC keygen (3 parties, 2-of-3)...")
	w, err := wallet.New(parties, threshold, rpcURL)
	if err != nil {
		return nil, err
	}

	if err := w.Save(keysFile); err != nil {
		return nil, fmt.Errorf("save keys: %w", err)
	}
	fmt.Printf("Key shares saved to %s — fund this address and re-run:\n", keysFile)
	fmt.Printf("  %s\n\n", w.Address().Hex())
	return w, nil
}
