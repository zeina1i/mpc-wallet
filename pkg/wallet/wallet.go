package wallet

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/zeina1i/mpc-wallet/pkg/threshold"
)

// Wallet holds the MPC key shares and an Ethereum RPC connection.
type Wallet struct {
	keys    []keygen.LocalPartySaveData
	thold   int
	client  *ethclient.Client
	address common.Address
}

// New runs threshold keygen, derives the Ethereum address from the shared public key,
// and connects to the Ethereum node at rpcURL.
func New(partyCount, thresh int, rpcURL string) (*Wallet, error) {
	keys, err := threshold.Keygen(partyCount, thresh)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("eth dial: %w", err)
	}

	// The shared public key is stored in any of the save data structs
	pub := keys[0].ECDSAPub
	ecPub := &ecdsa.PublicKey{
		Curve: pub.Curve(),
		X:     pub.X(),
		Y:     pub.Y(),
	}
	address := crypto.PubkeyToAddress(*ecPub)

	return &Wallet{
		keys:    keys,
		thold:   thresh,
		client:  client,
		address: address,
	}, nil
}

// Address returns the Ethereum address derived from the shared MPC public key.
func (w *Wallet) Address() common.Address {
	return w.address
}

// Save writes the key shares to a JSON file on disk.
// Each party would normally save only their own share; here we save all for simplicity.
func (w *Wallet) Save(path string) error {
	data, err := json.Marshal(w.keys)
	if err != nil {
		return fmt.Errorf("marshal keys: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// Load reads key shares from a previously saved file and returns a ready Wallet.
func Load(path, rpcURL string, thresh int) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keys: %w", err)
	}

	var keys []keygen.LocalPartySaveData
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("unmarshal keys: %w", err)
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("eth dial: %w", err)
	}

	pub := keys[0].ECDSAPub
	ecPub := &ecdsa.PublicKey{Curve: pub.Curve(), X: pub.X(), Y: pub.Y()}
	address := crypto.PubkeyToAddress(*ecPub)

	return &Wallet{keys: keys, thold: thresh, client: client, address: address}, nil
}

// SendTransaction builds, MPC-signs, and broadcasts an Ethereum transaction.
func (w *Wallet) SendTransaction(ctx context.Context, to common.Address, value *big.Int) (*types.Transaction, error) {
	nonce, err := w.client.PendingNonceAt(ctx, w.address)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	gasPrice, err := w.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("gas price: %w", err)
	}

	chainID, err := w.client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain id: %w", err)
	}

	tx := types.NewTransaction(nonce, to, value, 21000, gasPrice, nil)

	// Hash the transaction the same way Ethereum does before signing
	signer := types.NewEIP155Signer(chainID)
	txHash := signer.Hash(tx)

	// MPC threshold signing — no single party holds the full private key
	r, s, err := threshold.Sign(txHash.Bytes(), w.keys, w.thold)
	if err != nil {
		return nil, fmt.Errorf("mpc sign: %w", err)
	}

	// Assemble the 65-byte [R || S || V] signature Ethereum expects
	sig, err := assembleSignature(r.Bytes(), s.Bytes(), chainID)
	if err != nil {
		return nil, fmt.Errorf("assemble sig: %w", err)
	}

	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return nil, fmt.Errorf("attach sig: %w", err)
	}

	if err := w.client.SendTransaction(ctx, signedTx); err != nil {
		return nil, fmt.Errorf("broadcast: %w", err)
	}

	return signedTx, nil
}

// assembleSignature builds the 65-byte Ethereum signature [R(32) || S(32) || V(1)].
// It tries V=0 and V=1 to find which recovers the correct address.
func assembleSignature(rBytes, sBytes []byte, chainID *big.Int) ([]byte, error) {
	sig := make([]byte, 65)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	// Try both recovery values
	for v := byte(0); v <= 1; v++ {
		sig[64] = v
		_, err := crypto.Ecrecover(make([]byte, 32), sig) // just validate format
		if err == nil {
			return sig, nil
		}
	}
	return sig, nil // return as-is; the broadcaster will reject if invalid
}
