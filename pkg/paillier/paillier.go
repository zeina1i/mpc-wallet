package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var one = big.NewInt(1)

// PublicKey for encryption
type PublicKey struct {
	N  *big.Int // Modulus N = p*q
	G  *big.Int // Generator, g = N+1
	N2 *big.Int // N squared, the working modulus
}

// PrivateKey for decryption
type PrivateKey struct {
	Lambda    *big.Int // lcm(p-1, q-1)
	Mu        *big.Int // L(g^lambda mod N²)^(-1) mod N
	PublicKey *PublicKey
}

// Ciphertext is encrypted value
type Ciphertext struct {
	C *big.Int
}

// l computes the L function: L(x) = (x-1) / n
func l(x, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}

// lcm computes the least common multiple of a and b
func lcm(a, b *big.Int) *big.Int {
	gcd := new(big.Int).GCD(nil, nil, a, b)
	return new(big.Int).Div(new(big.Int).Mul(a, b), gcd)
}

// GenerateKeyPair creates public/private keys.
// bits is the key size (e.g., 2048). p and q are each bits/2 long.
func GenerateKeyPair(bits int) (*PublicKey, *PrivateKey, error) {
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, fmt.Errorf("generate p: %w", err)
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, fmt.Errorf("generate q: %w", err)
	}

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)

	// lambda = lcm(p-1, q-1)
	p1 := new(big.Int).Sub(p, one)
	q1 := new(big.Int).Sub(q, one)
	lambda := lcm(p1, q1)

	// g = N + 1 is the standard simplification; L(g^lambda mod N²) = lambda
	g := new(big.Int).Add(n, one)

	// mu = L(g^lambda mod N²)^(-1) mod N
	gLambda := new(big.Int).Exp(g, lambda, n2)
	lVal := l(gLambda, n)
	mu := new(big.Int).ModInverse(lVal, n)
	if mu == nil {
		return nil, nil, fmt.Errorf("mu has no modular inverse (bad primes)")
	}

	pub := &PublicKey{N: n, G: g, N2: n2}
	priv := &PrivateKey{Lambda: lambda, Mu: mu, PublicKey: pub}
	return pub, priv, nil
}

// Encrypt encodes plaintext m into a ciphertext.
// c = g^m * r^N mod N²   where r is a random value with gcd(r,N)=1
func Encrypt(pub *PublicKey, m *big.Int) (*Ciphertext, error) {
	if m.Sign() < 0 || m.Cmp(pub.N) >= 0 {
		return nil, fmt.Errorf("plaintext must be in [0, N)")
	}

	// Pick random r in [1, N); for large N the chance gcd(r,N)>1 is negligible
	r, err := rand.Int(rand.Reader, pub.N)
	if err != nil {
		return nil, fmt.Errorf("generate r: %w", err)
	}
	if r.Sign() == 0 {
		r.SetInt64(1)
	}

	// c = g^m * r^N mod N²
	gm := new(big.Int).Exp(pub.G, m, pub.N2)
	rN := new(big.Int).Exp(r, pub.N, pub.N2)
	c := new(big.Int).Mod(new(big.Int).Mul(gm, rN), pub.N2)

	return &Ciphertext{C: c}, nil
}

// Decrypt recovers the plaintext from a ciphertext.
// m = L(c^lambda mod N²) * mu mod N
func Decrypt(priv *PrivateKey, ct *Ciphertext) (*big.Int, error) {
	pub := priv.PublicKey

	cLambda := new(big.Int).Exp(ct.C, priv.Lambda, pub.N2)
	lVal := l(cLambda, pub.N)
	m := new(big.Int).Mod(new(big.Int).Mul(lVal, priv.Mu), pub.N)

	return m, nil
}

// Add combines two ciphertexts homomorphically: Decrypt(Add(E(m1), E(m2))) = m1+m2 mod N
// This works because E(m1)*E(m2) mod N² = E(m1+m2).
func Add(pub *PublicKey, c1, c2 *Ciphertext) *Ciphertext {
	c := new(big.Int).Mod(new(big.Int).Mul(c1.C, c2.C), pub.N2)
	return &Ciphertext{C: c}
}

// Multiply scales a ciphertext by a plaintext constant k: Decrypt(Multiply(E(m), k)) = m*k mod N
// This works because E(m)^k mod N² = E(m*k).
func Multiply(pub *PublicKey, ct *Ciphertext, k *big.Int) *Ciphertext {
	c := new(big.Int).Exp(ct.C, k, pub.N2)
	return &Ciphertext{C: c}
}
