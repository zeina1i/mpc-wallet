package mta

import (
	"crypto/rand"
	"math/big"

	"github.com/zeina1i/mpc-wallet/pkg/paillier"
)

// MtA stands for Multiplicative-to-Additive.
// Given Alice holds `a` and Bob holds `b`, the protocol produces
// additive shares α and β such that:
//
//	α + β = a * b  (mod q)
//
// Neither party learns the other's input.
// The protocol uses Paillier's homomorphic addition and scalar multiplication.
//
// Protocol overview:
//
//	Step 1 (Alice → Bob): Alice encrypts her value and sends it
//	Step 2 (Bob):         Bob blinds the ciphertext with his value and a random mask
//	Step 3 (Alice):       Alice decrypts to recover her share
//	Result:               Alice holds α, Bob holds β, and α + β = a*b mod q

// AliceOutput is what Alice holds after the protocol
type AliceOutput struct {
	Alpha *big.Int // Alice's additive share: α
}

// BobOutput is what Bob holds after the protocol
type BobOutput struct {
	Beta         *big.Int             // Bob's additive share: β
	MaskedCipher *paillier.Ciphertext // the ciphertext Alice needs to decrypt
}

// Step1Alice runs Alice's first step.
// Alice encrypts her secret `a` with her Paillier public key and sends the ciphertext to Bob.
func Step1Alice(pub *paillier.PublicKey, a *big.Int) (*paillier.Ciphertext, error) {
	cipherText, err := paillier.Encrypt(pub, a)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

// Step2Bob runs Bob's step.
// Bob receives Alice's ciphertext c_A = Enc(a).
// He picks a random mask β, then computes:
//
//	c_B = c_A^b * Enc(-β) mod N²  =  Enc(a*b - β)
//
// Bob keeps β as his additive share and sends c_B back to Alice.
func Step2Bob(pub *paillier.PublicKey, cA *paillier.Ciphertext, b, q *big.Int) (*BobOutput, error) {
	beta, err := rand.Int(rand.Reader, q)
	if err != nil {
		return nil, err
	}

	cAB := paillier.Multiply(pub, cA, b)

	negBeta := new(big.Int).Sub(pub.N, new(big.Int).Mod(beta, pub.N))
	encNegBeta, err := paillier.Encrypt(pub, negBeta)
	if err != nil {
		return nil, err
	}

	cB := paillier.Add(pub, cAB, encNegBeta)
	return &BobOutput{Beta: beta, MaskedCipher: cB}, nil
}

// Step3Alice runs Alice's final step.
// Alice decrypts c_B to recover:
//
//	α = Dec(c_B) = a*b - β  (mod q)
func Step3Alice(priv *paillier.PrivateKey, bobOut *BobOutput, q *big.Int) (*AliceOutput, error) {
	alpha, _ := paillier.Decrypt(priv, bobOut.MaskedCipher)
	alpha.Mod(alpha, q) // bring into [0, q)
	return &AliceOutput{Alpha: alpha}, nil
}
