package paillier

import "math/big"

// PublicKey for encryption
type PublicKey struct {
	N  *big.Int // Modulus
	G  *big.Int // Generator
	N2 *big.Int // N squared
}

// PrivateKey for decryption
type PrivateKey struct {
	Lambda    *big.Int
	Mu        *big.Int
	PublicKey *PublicKey
}

// Ciphertext is encrypted value
type Ciphertext struct {
	C *big.Int
}

// GenerateKeyPair creates public/private keys
// bits: key size (e.g., 2048)
//func GenerateKeyPair(bits int) (*PublicKey, *PrivateKey, error)

// Encrypt a plaintext message
//func Encrypt(pub *PublicKey, m *big.Int) (*Ciphertext, error)

// Decrypt a ciphertext
//func Decrypt(priv *PrivateKey, c *Ciphertext) (*big.Int, error)

// Add two ciphertexts: E(m1) + E(m2) = E(m1+m2)
//func Add(pub *PublicKey, c1, c2 *Ciphertext) *Ciphertext

// Multiply ciphertext by constant: E(m) * k = E(m*k)
//func Multiply(pub *PublicKey, c *Ciphertext, k *big.Int) *Ciphertext
